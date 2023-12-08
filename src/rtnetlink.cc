#include "rtnetlink.hh"

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
  netlink_route.ReceiveT<RTM_NEWROUTE, rtmsg>(
      [&](rtmsg &rtm, Netlink::Attrs attrs) {
        Route route = {};
        route.rtm = rtm;
        route.dst_mask = IP::NetmaskFromPrefixLength(route.rtm.rtm_dst_len);
        for (auto &attr : attrs) {
          switch (attr.type) {
          case RTA_OIF:
            route.oif = attr.As<U32>();
            break;
          case RTA_PREFSRC:
            route.prefsrc = attr.As<IP>();
            break;
          case RTA_DST:
            route.dst = attr.As<IP>();
            break;
          case RTA_TABLE:
            // this is always RT_TABLE_MAIN
            assert(attr.As<int>() == RT_TABLE_MAIN);
            break;
          case RTA_PRIORITY:
            route.priority = attr.As<U32>();
            break;
          case RTA_GATEWAY:
            route.gateway = attr.As<IP>();
            break;
          }
        }
        callback(route);
      },
      status);
}

Str ToStr(const Route &r) {
  return "Route{dst=" + ToStr(r.dst) + ", dst_mask=" + ToStr(r.dst_mask) +
         ", oif=" + (r.oif ? maf::ToStr(*r.oif) : "none") +
         ", prefsrc=" + (r.prefsrc ? maf::ToStr(*r.prefsrc) : "none") +
         ", gateway=" + (r.gateway ? maf::ToStr(*r.gateway) : "none") +
         ", priority=" + (r.priority ? maf::ToStr(*r.priority) : "none") + "}";
}

} // namespace maf::rtnetlink