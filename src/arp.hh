#pragma once

#include <string>

#include "ip.hh"
#include "mac.hh"

namespace maf::arp {

void Set(const std::string &interface, maf::IP ip, MAC mac, int af_inet_fd,
         Status &status);

} // namespace maf::arp