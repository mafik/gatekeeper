#pragma once

#include <sys/types.h>

#include "fn.hh"
#include "path.hh"
#include "status.hh"
#include "str.hh"

namespace maf {

struct VFile {
  Str path;
  Str content;
};

// Read the given file and call the callback with the file content.
void ReadRealFile(const Path &, Fn<void(StrView)> callback, Status &);

// Read the given file and call the callback with the file content.
//
// Files are usually served from the embedded filesystem. However if a real file
// with the same path exists - it overrides the embedded one. This can be used
// for development - so that you don't have to recompile the program every time
// you change a file.
void ReadFile(const Path &, Fn<void(StrView)> callback, Status &);

// Write the given file with the given contents.
void WriteFile(const Path &, StrView contents, Status &, mode_t = 0644);

void CopyFile(const Path &from, const Path &to, Status &, mode_t = 0644);

} // namespace maf