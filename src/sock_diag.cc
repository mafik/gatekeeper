#include "sock_diag.hh"

#include <linux/inet_diag.h>
#include <linux/packet_diag.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>

#include "netlink.hh"
#include "str.hh"

namespace maf {

void ScanPacketSockets(Fn<void(PacketSocketDescription &)> callback,
                       Status &status) {
  Netlink netlink_diag(NETLINK_SOCK_DIAG, status);
  if (!OK(status)) {
    status() += "Couldn't establish netlink to NETLINK_SOCK_DIAG. Maybe kernel "
                "module \"netlink-diag\" is missing?";
    return;
  }
  struct {
    struct nlmsghdr nlh;
    struct packet_diag_req req;
  } req = {.nlh = {.nlmsg_len = sizeof(req),
                   .nlmsg_type = SOCK_DIAG_BY_FAMILY,
                   .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP},
           .req = {
               .sdiag_family = AF_PACKET,
               .sdiag_protocol = 0,
               .pdiag_show = 0,
           }};
  netlink_diag.Send(req.nlh, status);
  if (!OK(status)) {
    status() += "Couldn't request the list of internet sockets from the kernel";
  }
  netlink_diag.ReceiveT<SOCK_DIAG_BY_FAMILY, packet_diag_msg>(
      [&](packet_diag_msg &msg, Netlink::Attrs attributes) {
        PacketSocketDescription desc{
            .protocol = msg.pdiag_num,
            .inode = msg.pdiag_ino,
        };
        callback(desc);
      },
      status);
  if (!OK(status)) {
    status() += "Couldn't receive the list of internet sockets from the kernel";
  }
}

static void ScanInternetSockets(U8 protocol,
                                Fn<void(InternetSocketDescription &)> callback,
                                Status &status) {
  Netlink netlink_diag(NETLINK_SOCK_DIAG, status);
  if (!OK(status)) {
    status() += "Couldn't establish netlink to NETLINK_SOCK_DIAG. Maybe kernel "
                "module \"netlink-diag\" is missing?";
    return;
  }
  struct {
    struct nlmsghdr nlh;
    struct inet_diag_req_v2 idr;
  } req = {.nlh = {.nlmsg_len = sizeof(req),
                   .nlmsg_type = SOCK_DIAG_BY_FAMILY,
                   .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP},
           .idr = {.sdiag_family = AF_INET,
                   .sdiag_protocol = protocol,
                   .idiag_ext = 0,
                   .idiag_states = (U32)-1,
                   .id = {}}};
  netlink_diag.Send(req.nlh, status);
  if (!OK(status)) {
    status() += "Couldn't request the list of internet sockets from the kernel";
  }
  netlink_diag.ReceiveT<SOCK_DIAG_BY_FAMILY, inet_diag_msg>(
      [&](inet_diag_msg &msg, Netlink::Attrs attributes) {
        InternetSocketDescription desc{
            .local_ip = IP(msg.id.idiag_src[0]),
            .local_port = ntohs(msg.id.idiag_sport),
            .remote_ip = IP(msg.id.idiag_dst[0]),
            .remote_port = ntohs(msg.id.idiag_dport),
            .inode = msg.idiag_inode,
            .uid = msg.idiag_uid,
            .interface = msg.id.idiag_if,
        };
        callback(desc);
      },
      status);
  if (!OK(status)) {
    status() += "Couldn't receive the list of internet sockets from the kernel";
  }
}

void ScanUdpSockets(Fn<void(InternetSocketDescription &)> callback,
                    Status &status) {
  ScanInternetSockets(IPPROTO_UDP, callback, status);
}

void ScanTcpSockets(Fn<void(InternetSocketDescription &)> callback,
                    Status &status) {
  ScanInternetSockets(IPPROTO_TCP, callback, status);
}

} // namespace maf