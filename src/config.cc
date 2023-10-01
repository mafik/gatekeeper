#include "config.hh"

// Domain used to access hosts in the local network. Hardcoded to "lan".
const std::string kLocalDomain = "lan";

// Default values will be overwritten during startup.
Interface lan = {.name = "eth0", .index = 0};
maf::IP lan_ip = {192, 168, 1, 1};
maf::Network lan_network = {.ip = {192, 168, 1, 0},
                            .netmask = {255, 255, 255, 0}};

Interface wan = {.name = "eth1", .index = 1};
maf::IP wan_ip = {192, 168, 2, 1};
