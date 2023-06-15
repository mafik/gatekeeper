#include "virtual_fs.hh"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../generated/embedded.hh"
#include "log.hh"

namespace gatekeeper {

void ReadRealFile(const char *path,
                  std::function<void(std::string_view)> callback,
                  Status &status) {
  struct stat buffer;
  if (stat(path, &buffer) != 0) {
    status() += "Failed to stat " + std::string(path);
    return;
  }
  int f = open(path, O_RDONLY);
  if (f == -1) {
    status() += "Failed to open " + std::string(path);
    return;
  }
  char buf[buffer.st_size + 1];
  int len = read(f, buf, sizeof(buf));
  if (len == -1) {
    status() += "Failed to read " + std::string(path);
    close(f);
    return;
  }
  close(f);
  callback(std::string_view(buf, len));
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
  callback(it->second->content);
}

} // namespace gatekeeper