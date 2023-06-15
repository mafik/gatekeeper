#pragma once

#include <functional>
#include <string>

#include "status.hh"

namespace gatekeeper {

struct VFile {
  std::string path;
  std::string content;
};

// Read the given file and call the callback with the file content.
//
// Files are usually served from the embedded filesystem. However if a real file
// with the same path exists - it overrides the embedded one. This can be used
// for development - so that you don't have to recompile the program every time
// you change a file.
void ReadFile(const char *path, std::function<void(std::string_view)> callback,
              Status &);

} // namespace gatekeeper