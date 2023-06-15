#include "virtual_fs.hh"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../generated/embedded.hh"
#include "log.hh"

namespace gatekeeper {

void ReadRealFile(const char *path,
                  std::function<void(std::string_view)> callback,
                  Status &status) {
  int f = open(path, O_RDONLY);
  if (f == -1) {
    status() += "Failed to open " + std::string(path);
    return;
  }
  struct stat buffer;
  if (fstat(f, &buffer) != 0) {
    status() += "Failed to fstat " + std::string(path);
    close(f);
    return;
  }
  void *ptr = mmap(nullptr, buffer.st_size, PROT_READ, MAP_PRIVATE, f, 0);
  if (ptr == MAP_FAILED) {
    status() += "Failed to mmap " + std::string(path);
    close(f);
    return;
  }
  close(f);
  callback(std::string_view((char *)ptr, buffer.st_size));
  munmap(ptr, buffer.st_size);
}

void ReadFile(const char *path, std::function<void(std::string_view)> callback,
              Status &status) {
  // Try reading the real file first.
  ReadRealFile(path, callback, status);
  if (status.Ok()) {
    return;
  }
  // Fallback to embedded filesystem.
  auto it = embedded::index.find(path);
  if (it == embedded::index.end()) {
    status() += "Embedded file not found: " + std::string(path);
    return;
  }
  status.Reset();
  callback(it->second->content);
}

void WriteFile(const char *path, std::string_view contents, Status &status,
               mode_t mode) {
  int f = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
  if (f == -1) {
    status() += "Failed to open " + std::string(path);
    return;
  }
  if (write(f, contents.data(), contents.size()) != (ssize_t)contents.size()) {
    status() += "Failed to write " + std::string(path);
    close(f);
    return;
  }
  close(f);
}

void CopyFile(const char *from_path, const char *to_path, Status &status,
              mode_t mode) {
  int fd_from = open(from_path, O_RDONLY);
  if (fd_from == -1) {
    status() += "Failed to open " + std::string(from_path);
    // Try reading the file from the embedded filesystem.
    Status vfs_status;
    ReadFile(
        from_path,
        [&](std::string_view contents) {
          gatekeeper::WriteFile(to_path, contents, vfs_status);
        },
        vfs_status);
    if (vfs_status.Ok()) {
      status.Reset();
    }
    return;
  }
  int fd_to = open(to_path, O_WRONLY | O_CREAT | O_TRUNC, mode);
  if (fd_to == -1) {
    status() += "Failed to open " + std::string(to_path);
    close(fd_from);
    return;
  }
  struct stat buffer;
  if (fstat(fd_from, &buffer) != 0) {
    status() += "Failed to fstat " + std::string(from_path);
    close(fd_from);
    close(fd_to);
    return;
  }
  if (sendfile(fd_to, fd_from, nullptr, buffer.st_size) != buffer.st_size) {
    status() += "Failed to sendfile " + std::string(from_path);
    close(fd_from);
    close(fd_to);
    return;
  }
  close(fd_from);
  close(fd_to);
}

} // namespace gatekeeper