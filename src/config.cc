#include "config.hh"

const std::string kLocalDomain = "local";

// Default values will be overwritten during startup.
Interface lan = {.name = "eth0", .index = 0};
IP lan_ip = {192, 168, 1, 1};
Network lan_network = {.ip = {192, 168, 1, 0}, .netmask = {255, 255, 255, 0}};

Interface wan = {.name = "eth1", .index = 1};
IP wan_ip = {192, 168, 2, 1};
