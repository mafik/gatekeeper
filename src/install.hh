#pragma once

#include "status.hh"

namespace gatekeeper::install {

bool CanInstall();
void Install(maf::Status &status);

} // namespace gatekeeper::install