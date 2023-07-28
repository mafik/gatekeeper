#pragma once

// Functions for doing cleanup at program exit.

#include "fn.hh"

namespace maf {

// Register a function to be called at program exit.
void AtExit(Fn<void()>);

void ExitCleanup();

} // namespace maf