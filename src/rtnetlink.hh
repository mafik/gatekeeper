#pragma once

#include <linux/rtnetlink.h>

#include "ip.hh"
#include "netlink.hh"
#include "optional.hh"
#include "status.hh"
#include "str.hh"

// Utilities for interacting with the Linux routing table.
//
// See `man 7 rtnetlink`.
namespace maf::rtnetlink {

struct Route {
  rtmsg rtm;
  Optional<U32> oif;
  IP dst; // Route applies if the destination IP matches route `dst` (when
          // both are masked by dst_mask).
  IP dst_mask;
  Optional<IP> prefsrc; // Preferred source address in cases where more
                        // than one source address could be used.
  Optional<IP> gateway;
  Optional<U32> priority;
};

Str ToStr(const Route &);
static_assert(Stringer<Route>);

void GetRoute(Netlink &netlink_route, std::function<void(Route &)> callback,
              Status &status);

} // namespace maf::rtnetlink