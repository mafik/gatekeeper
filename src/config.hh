#pragma once

#include <string>

#include "interface.hh"
#include "ip.hh"
#include "vec.hh"

extern const std::string kLocalDomain;

// Those values could actually be fetched from the kernel each time they're
// needed. This might be useful if the network configuration changes while the
// program is running. If this ever becomes a problem, just remove those
// variables.

extern maf::Interface lan;
extern maf::IP lan_ip;
extern maf::Network lan_network;

extern maf::Vec<maf::Interface> lan_bridge_slaves;

extern maf::Interface wan;
extern maf::IP wan_ip;
