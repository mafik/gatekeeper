#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <cassert>
#include <functional>
#include <optional>

#include "fd.hh"
#include "format.hh"
#include "log.hh"
#include "status.hh"

// This file is currently unused because ioctls turned out to be way simpler.
//
// It seems that some things are best done through netlink so this code is kept
// for later use.

// Example usage:
//
// Rtnetlink netlink;
// netlink.GetRoute([&](Rtnetlink::Route &route) {
//   if (!route.oif.has_value()) {
//     return;
//   }
//   if (route.rtm.rtm_protocol == RTPROT_DHCP) {
//     for (auto &iface : interfaces) {
//       if (iface.index == route.oif) {
//         iface.area = Interface::Classification::WAN;
//         LOG << "Interface " << iface.name
//             << " is WAN because it was configured by DHCP";
//       }
//     }
//   }
// });

struct Rtnetlink {
  Status status;
  FD fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  sockaddr_nl local = {
      .nl_family = AF_NETLINK,
      .nl_pid = 0,
      .nl_groups = 0,
  };
  uint32_t seq = 1;
  Rtnetlink() {
    if (fd < 0) {
      status() += "socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)";
      return;
    }
    int sndbuf = 32 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    int recvbuf = 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &recvbuf, sizeof(recvbuf));
    int one = 1;
    setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one));
    if (bind(fd, (sockaddr *)&local, sizeof(local)) < 0) {
      status() += "bind(AF_NETLINK)";
      return;
    }
    socklen_t addr_len = sizeof(local);
    if (getsockname(fd, (sockaddr *)&local, &addr_len) < 0) {
      status() += "getsockname(AF_NETLINK)";
      return;
    }
    setsockopt(fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK, &one, sizeof(one));
  }

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
  };

  void GetRoute(std::function<void(Route &)> callback) {
    if (!status.Ok()) {
      return;
    }
    struct {
      struct nlmsghdr nlh;
      struct rtmsg rtm;
    } req = {.nlh = {.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
                     .nlmsg_type = RTM_GETROUTE,
                     .nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST,
                     .nlmsg_seq = seq++},
             .rtm = {
                 .rtm_family = AF_INET,
                 .rtm_table = RT_TABLE_MAIN,
             }};
    send(fd, &req, req.nlh.nlmsg_len, 0);
    char buf[1024 * 32];
    ssize_t len = recv(fd, buf, sizeof(buf), 0);
    if (len < 0) {
      status() += "recv(AF_NETLINK)";
      return;
    }
    int i = 0;
    while (i < len) {
      nlmsghdr *nlh = (nlmsghdr *)(buf + i);
      int next = i + nlh->nlmsg_len;

      // LOG << dump_struct(*nlh);
      i += sizeof(nlmsghdr);

      rtmsg *rtm = (rtmsg *)(buf + i);
      // LOG << dump_struct(*rtm);
      i += sizeof(rtmsg);

      Route route = {};
      route.rtm = *rtm;
      route.dst_mask = IP::NetmaskFromPrefixLength(rtm->rtm_dst_len);

      while (i < next - sizeof(rtattr)) {
        rtattr *rta = (rtattr *)(buf + i);
        i += sizeof(rtattr);
        if (rta->rta_type == RTA_OIF) {
          route.oif = *(uint32_t *)(buf + i);
        } else if (rta->rta_type == RTA_PREFSRC) {
          route.prefsrc = IP(*(uint32_t *)(buf + i));
        } else if (rta->rta_type == RTA_DST) {
          route.dst = IP(*(uint32_t *)(buf + i));
        } else if (rta->rta_type == RTA_TABLE) {
          // this is always RT_TABLE_MAIN
          unsigned char table = *(unsigned char *)(buf + i);
          assert(table == RT_TABLE_MAIN);
        } else if (rta->rta_type == RTA_PRIORITY) {
          route.priority = *(uint32_t *)(buf + i);
        } else if (rta->rta_type == RTA_GATEWAY) {
          route.gateway = IP(*(uint32_t *)(buf + i));
        } else {
          LOG << dump_struct(*rta);
          std::string hex;
          for (int j = 0; j < rta->rta_len - sizeof(rtattr); ++j) {
            hex += f("%02x", (uint8_t)(buf[i + j]));
          }
          LOG << "  " << hex;
        }
        i += rta->rta_len - sizeof(rtattr);
      }
      assert(i == next);

      callback(route);
    }
  }
};
