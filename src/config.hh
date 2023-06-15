#pragma once

#include <string>

#include "ip.hh"

extern const std::string kLocalDomain;

// Those values could actually be fetched from the kernel each time they're
// needed. This might be useful if the network configuration changes while the
// program is running. If this ever becomes a problem, just remove those
// variables.

extern std::string interface_name;
extern IP server_ip;
extern IP netmask;
