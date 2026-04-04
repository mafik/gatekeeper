#pragma once

#include "status.hh"

namespace gatekeeper {

void HookSignals(automat::Status &status);
void UnhookSignals();

extern const char *kKnownEnvironmentVariables[];

} // namespace gatekeeper