#pragma once

// Functions for working with the /proc filesystem.

#include "fn.hh"
#include "int.hh"
#include "status.hh"

namespace maf {

void ScanProcesses(Fn<void(U32 pid, Status &)> callback, Status &);
void ScanOpenedFiles(U32 pid, Fn<void(U32 fd, StrView path, Status &)>,
                     Status &);

} // namespace maf
