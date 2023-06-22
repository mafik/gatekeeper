#pragma once

#include <linux/rtnetlink.h>

#include <cstdint>
#include <optional>

#include "ip.hh"
#include "netlink.hh"
#include "status.hh"

// Utilities for interacting with the Linux routing table.
//
// See `man 7 rtnetlink`.
namespace maf::rtnetlink {

struct Route {
  rtmsg rtm;
  std::optional<uint32_t> oif;
  IP dst; // Route applies if the destination IP matches route `dst` (when
          // both are masked by dst_mask).
  IP dst_mask;
  std::optional<IP> prefsrc; // Preferred source address in cases where more
                             // than one source address could be used.
  std::optional<IP> gateway;
  std::optional<uint32_t> priority;

  std::string LoggableString() const;
};

void GetRoute(Netlink &netlink_route, std::function<void(Route &)> callback,
              Status &status);

} // namespace maf::rtnetlink