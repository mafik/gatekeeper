#include "virtual_fs.hh"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../build/generated/embedded.hh"

namespace maf {

void ReadRealFile(const Path &path, Fn<void(StrView)> callback,
                  Status &status) {
  int f = open(path, O_RDONLY);
  if (f == -1) {
    status() += "Failed to open " + Str(path);
    return;
  }
  struct stat buffer;
  if (fstat(f, &buffer) != 0) {
    status() += "Failed to fstat " + Str(path);
    close(f);
    return;
  }
  void *ptr = mmap(nullptr, buffer.st_size, PROT_READ, MAP_PRIVATE, f, 0);
  if (ptr == MAP_FAILED) {
    status() += "Failed to mmap " + Str(path);
    close(f);
    return;
  }
  close(f);
  callback(StrView((char *)ptr, buffer.st_size));
  munmap(ptr, buffer.st_size);
}

void ReadFile(const Path &path, Fn<void(StrView)> callback, Status &status) {
  auto expanded = path.ExpandUser();
  // Try reading the real file first.
  ReadRealFile(expanded, callback, status);
  if (status.Ok()) {
    return;
  }
  // Fallback to embedded filesystem.
  auto it = gatekeeper::embedded::index.find(expanded);
  if (it == gatekeeper::embedded::index.end()) {
    status() += "Embedded file not found: " + Str(expanded);
    return;
  }
  status.Reset();
  callback(it->second->content);
}

void WriteFile(const Path &path, StrView contents, Status &status,
               mode_t mode) {
  int f = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
  if (f == -1) {
    status() += "Failed to open " + Str(path);
    return;
  }
  if (write(f, contents.data(), contents.size()) != (ssize_t)contents.size()) {
    status() += "Failed to write " + Str(path);
    close(f);
    return;
  }
  close(f);
}

void CopyFile(const Path &from, const Path &to, Status &status, mode_t mode) {
  int fd_from = open(from, O_RDONLY);
  if (fd_from == -1) {
    status() += "Failed to open " + Str(from);
    // Try reading the file from the embedded filesystem.
    Status vfs_status;
    ReadFile(
        from, [&](StrView contents) { WriteFile(to, contents, vfs_status); },
        vfs_status);
    if (vfs_status.Ok()) {
      status.Reset();
    }
    return;
  }
  int fd_to = open(to, O_WRONLY | O_CREAT | O_TRUNC, mode);
  if (fd_to == -1) {
    status() += "Failed to open " + std::string(to);
    close(fd_from);
    return;
  }
  struct stat buffer;
  if (fstat(fd_from, &buffer) != 0) {
    status() += "Failed to fstat " + std::string(from);
    close(fd_from);
    close(fd_to);
    return;
  }
  if (sendfile(fd_to, fd_from, nullptr, buffer.st_size) != buffer.st_size) {
    status() += "Failed to sendfile " + std::string(from);
    close(fd_from);
    close(fd_to);
    return;
  }
  close(fd_from);
  close(fd_to);
}

} // namespace maf