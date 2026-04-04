#pragma once

#include <string>

#include "ip.hh"
#include "mac.hh"

namespace automat::arp {

void Set(const std::string &interface, automat::IP ip, MAC mac, int af_inet_fd,
         Status &status);

} // namespace automat::arp