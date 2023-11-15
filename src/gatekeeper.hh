#pragma once

#include "status.hh"

namespace gatekeeper {

void HookSignals(maf::Status &status);
void UnhookSignals();

extern const char *kKnownEnvironmentVariables[];

} // namespace gatekeeper