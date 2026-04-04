#pragma once

#include "status.hh"
#include "str.hh"

// Functions for interacting with the graphical desktop according to the X
// Desktop Group (XDG) standards.
namespace automat::xdg {

void Open(StrView path_or_url, Status &status);

} // namespace automat::xdg