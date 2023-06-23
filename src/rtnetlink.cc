#include "rtnetlink.hh"

#include <cassert>
#include <cstdint>

namespace maf::rtnetlink {

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
  netlink_route.ReceiveT<rtmsg>(
      RTM_NEWROUTE,
      [&](rtmsg &rtm, std::span<Netlink::Attr *> attr) {
        Route route = {};
        route.rtm = rtm;
        route.dst_mask = IP::NetmaskFromPrefixLength(route.rtm.rtm_dst_len);
        if (attr[RTA_OIF]) {
          route.oif = attr[RTA_OIF]->As<uint32_t>();
        }
        if (attr[RTA_PREFSRC]) {
          route.prefsrc = attr[RTA_PREFSRC]->As<IP>();
        }
        if (attr[RTA_DST]) {
          route.dst = attr[RTA_DST]->As<IP>();
        }
        if (attr[RTA_TABLE]) {
          // this is always RT_TABLE_MAIN
          int table = attr[RTA_TABLE]->As<int>();
          assert(table == RT_TABLE_MAIN);
        }
        if (attr[RTA_PRIORITY]) {
          route.priority = attr[RTA_PRIORITY]->As<uint32_t>();
        }
        if (attr[RTA_GATEWAY]) {
          route.gateway = attr[RTA_GATEWAY]->As<IP>();
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

} // namespace maf::rtnetlink