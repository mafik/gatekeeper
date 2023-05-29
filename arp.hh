#pragma once

#include <string>

#include "ip.hh"
#include "mac.hh"

namespace arp {

void Set(const std::string& interface, IP ip, MAC mac, int af_inet_fd, std::string &error);

} // namespace arp