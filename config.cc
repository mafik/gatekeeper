#include "config.hh"

const std::string kLocalDomain = "local";

// Default values will be overwritten during startup.
std::string interface_name = "eth0";
IP server_ip = {192, 168, 1, 1};
IP netmask = {255, 255, 255, 0};