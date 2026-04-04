#pragma once

#include "status.hh"

namespace gatekeeper::install {

bool CanInstall();
void Install(automat::Status &status);

} // namespace gatekeeper::install