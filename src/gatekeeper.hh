#pragma once

#include "status.hh"

namespace gatekeeper {

void HookSignals(maf::Status &status);
void UnhookSignals();

} // namespace gatekeeper