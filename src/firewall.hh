#pragma once

#include "status.hh"

namespace gatekeeper::firewall {

// Sets up netfilter hooks that intercept the traffic & starts a thread that
// processes it.
void Start(Status &status);

} // namespace gatekeeper::firewall