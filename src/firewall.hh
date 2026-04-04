#pragma once

#include "status.hh"

namespace gatekeeper::firewall {

// Sets up netfilter hooks that intercept the traffic & starts a thread that
// processes it.
void Start(automat::Status &status);

void Stop();

} // namespace gatekeeper::firewall