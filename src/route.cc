#include "route.hh"
#include "format.hh"
#include "log.hh"
#include <cassert>
#include <linux/rtnetlink.h>

namespace maf::route {

void GetRoute(Netlink &netlink_route, std::function<void(Route &)> callback,
              Status &status) {
  if (!status.Ok()) {
    return;
  }
  struct {
    nlmsghdr hdr{.nlmsg_len = sizeof(*this),
                 .nlmsg_type = RTM_GETROUTE,
                 .nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
                 .nlmsg_seq = 0};
    rtmsg msg{
        .rtm_family = AF_INET,
        .rtm_table = RT_TABLE_MAIN,
    };
  } req;
  netlink_route.Send(req.hdr, status);
  if (!status.Ok()) {
    return;
  }
  netlink_route.Receive(
      sizeof(rtmsg), RTA_MAX,
      [&](uint16_t type, void *fixed_message, nlattr **attr) {
        if (type != RTM_NEWROUTE) {
          return;
        }
        Route route = {};
        route.rtm = *(rtmsg *)fixed_message;
        route.dst_mask = IP::NetmaskFromPrefixLength(route.rtm.rtm_dst_len);
        if (attr[RTA_OIF]) {
          route.oif = *(uint32_t *)(attr[RTA_OIF] + 1);
        }
        if (attr[RTA_PREFSRC]) {
          route.prefsrc = IP(*(uint32_t *)(attr[RTA_PREFSRC] + 1));
        }
        if (attr[RTA_DST]) {
          route.dst = IP(*(uint32_t *)(attr[RTA_DST] + 1));
        }
        if (attr[RTA_TABLE]) {
          // this is always RT_TABLE_MAIN
          int table = *(int *)(attr[RTA_TABLE] + 1);
          assert(table == RT_TABLE_MAIN);
        }
        if (attr[RTA_PRIORITY]) {
          route.priority = *(uint32_t *)(attr[RTA_PRIORITY] + 1);
        }
        if (attr[RTA_GATEWAY]) {
          route.gateway = IP(*(uint32_t *)(attr[RTA_GATEWAY] + 1));
        }
        callback(route);
      },
      status);
}

std::string Route::LoggableString() const {
  return "Route{dst=" + dst.LoggableString() +
         ", dst_mask=" + dst_mask.LoggableString() +
         ", oif=" + (oif ? std::to_string(*oif) : "none") +
         ", prefsrc=" + (prefsrc ? prefsrc->LoggableString() : "none") +
         ", gateway=" + (gateway ? gateway->LoggableString() : "none") +
         ", priority=" + (priority ? std::to_string(*priority) : "none") + "}";
}

} // namespace maf::route