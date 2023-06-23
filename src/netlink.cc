#include "netlink.hh"
#include "format.hh"

#include <cstring>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <optional>
#include <string>

namespace maf {

static constexpr sockaddr_nl kKernelSockaddr{
    .nl_family = AF_NETLINK,
    .nl_pid = 0,
    .nl_groups = 0,
};

static constexpr uint32_t AttributeMax(uint32_t protocol, nlmsghdr &hdr) {
  switch (protocol) {
  case NETLINK_ROUTE:
    return RTA_MAX;
  case NETLINK_NETFILTER:
    switch (NFNL_SUBSYS_ID(hdr.nlmsg_type)) {
    case NFNL_SUBSYS_QUEUE:
      return NFQA_MAX;
    case NFNL_SUBSYS_NFTABLES:
      switch (NFNL_MSG_TYPE(hdr.nlmsg_type)) {
      case NFT_MSG_NEWTABLE:
      case NFT_MSG_GETTABLE:
      case NFT_MSG_DELTABLE:
        return NFTA_TABLE_MAX;
      case NFT_MSG_NEWCHAIN:
      case NFT_MSG_GETCHAIN:
      case NFT_MSG_DELCHAIN:
        return NFTA_CHAIN_MAX;
      case NFT_MSG_NEWRULE:
      case NFT_MSG_GETRULE:
      case NFT_MSG_DELRULE:
        return NFTA_RULE_MAX;
      case NFT_MSG_NEWSET:
      case NFT_MSG_GETSET:
      case NFT_MSG_DELSET:
        return NFTA_SET_MAX;
      case NFT_MSG_NEWSETELEM:
      case NFT_MSG_GETSETELEM:
      case NFT_MSG_DELSETELEM:
        return NFTA_SET_ELEM_MAX;
      case NFT_MSG_NEWGEN:
      case NFT_MSG_GETGEN:
        return NFTA_GEN_MAX;
      case NFT_MSG_TRACE:
        return NFTA_TRACE_MAX;
      case NFT_MSG_NEWOBJ:
      case NFT_MSG_GETOBJ:
      case NFT_MSG_DELOBJ:
      case NFT_MSG_GETOBJ_RESET:
        return NFTA_OBJ_MAX;
      case NFT_MSG_NEWFLOWTABLE:
      case NFT_MSG_GETFLOWTABLE:
      case NFT_MSG_DELFLOWTABLE:
        return NFTA_FLOWTABLE_MAX;
      default:
        return -1; // unknown nf_tables message
      }
    default:
      return -1; // unknown netlink subsystem
    }
  default: // unknown protocol (should have been reported in the constructor)
    return -1;
  }
}

Netlink::Netlink(int protocol, Status &status) : protocol(protocol) {
  switch (protocol) {
  case NETLINK_ROUTE:
    fixed_message_size = sizeof(rtmsg);
    break;
  case NETLINK_NETFILTER:
    fixed_message_size = sizeof(nfgenmsg);
    break;
  default:
    status() += "Unknown netlink protocol " + std::to_string(protocol);
    return;
  }
  fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol);
  if (fd < 0) {
    status() += "socket(AF_NETLINK, SOCK_RAW, " + f("%x", protocol) + ")";
    return;
  }
  int sndbuf = 32 * 1024;
  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
    status() += "setsockopt(SO_SNDBUF)";
    return;
  }
  int recvbuf = 1024 * 1024;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &recvbuf, sizeof(recvbuf)) < 0) {
    status() += "setsockopt(SO_RCVBUF)";
    return;
  }
  int one = 1;
  if (setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one)) < 0) {
    status() += "setsockopt(NETLINK_EXT_ACK)";
    return;
  }
  if (setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &one, sizeof(one)) < 0) {
    status() += "setsockopt(NETLINK_CAP_ACK)";
    return;
  }
  if (setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof(one)) < 0) {
    status() += "setsockopt(NETLINK_NO_ENOBUFS)";
    return;
  }
  if (setsockopt(fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK, &one, sizeof(one)) <
      0) {
    status() += "setsockopt(NETLINK_GET_STRICT_CHK)";
    return;
  }
  sockaddr_nl local = {
      .nl_family = AF_NETLINK,
      .nl_pid = 0,
      .nl_groups = 0,
  };
  if (bind(fd, (sockaddr *)&local, sizeof(local)) < 0) {
    status() += "bind(AF_NETLINK)";
    return;
  }
}

void Netlink::Send(nlmsghdr &msg, Status &status) {
  msg.nlmsg_seq = seq++;
  SendRaw(std::string_view((char *)&msg, msg.nlmsg_len), status);
}

void Netlink::SendWithAttr(nlmsghdr &hdr, Attr &attr, Status &status) {
  uint16_t hdr_len = hdr.nlmsg_len;

  hdr.nlmsg_seq = seq++;
  hdr.nlmsg_len += attr.len;

  iovec iov[2] = {
      {
          .iov_base = &hdr,
          .iov_len = hdr_len,
      },
      {
          .iov_base = &attr,
          .iov_len = attr.len,
      },
  };
  msghdr msg{
      .msg_name = (void *)&kKernelSockaddr,
      .msg_namelen = sizeof(kKernelSockaddr),
      .msg_iov = iov,
      .msg_iovlen = 2,
  };

  ssize_t len = sendmsg(fd, &msg, 0);
  if (len < 0) {
    status() += "sendmsg(AF_NETLINK)";
    return;
  }
}

void Netlink::SendRaw(std::string_view raw, Status &status) {
  ssize_t len = sendto(fd, raw.data(), raw.size(), 0,
                       (sockaddr *)&kKernelSockaddr, sizeof(kKernelSockaddr));
  if (len < 0) {
    status() += "sendto(AF_NETLINK)";
    return;
  }
}

void Netlink::Receive(ReceiveCallback callback, Status &status) {
  bool expect_more_messages = true;
  while (expect_more_messages) {
    char buf[1024 * 32];
    ssize_t len = recv(fd, buf, sizeof(buf), 0);
    if (len < 0) {
      status() += "recv(AF_NETLINK)";
      return;
    }

    char *buf_iter = buf;
    char *buf_end = buf + len;

    while (buf_iter < buf_end - sizeof(nlmsghdr)) {

      nlmsghdr *hdr = (nlmsghdr *)(buf_iter);
      buf_iter += sizeof(nlmsghdr);

      if (hdr->nlmsg_type == NLMSG_ERROR) {
        char *end = (char *)(hdr) + hdr->nlmsg_len;
        int err = *(int *)(buf_iter);
        buf_iter += sizeof(int);
        std::string msg;
        if (err == 0) {
          return; // This was a regular ACK - ignore it
        }
        nlmsghdr *myhdr = (nlmsghdr *)(buf_iter);
        if (hdr->nlmsg_flags & NLM_F_CAPPED) { // payload was truncated
          buf_iter += sizeof(nlmsghdr);
        } else {
          buf_iter += myhdr->nlmsg_len;
        }
        msg += "Netlink error";
        msg += "\nError header:\n";
        msg += dump_struct(*hdr);
        msg += "\nOriginal request:\n";
        msg += dump_struct(*myhdr);

        if (hdr->nlmsg_flags & NLM_F_ACK_TLVS) {
          nlattr *err_attrs[NLMSGERR_ATTR_MAX + 1] = {};
          while (buf_iter < end - sizeof(nlattr)) {
            buf_iter = (char *)(((uintptr_t)buf_iter + 3) & ~3);
            nlattr *a = (nlattr *)(buf_iter);
            if (a->nla_type != NLMSGERR_ATTR_MSG &&
                a->nla_type != NLMSGERR_ATTR_OFFS) {
              msg += dump_struct(*a);
            }
            err_attrs[a->nla_type] = a;
            buf_iter += a->nla_len;
          }
          if (err_attrs[NLMSGERR_ATTR_MSG]) {
            msg += " error message: ";
            msg += (char *)(err_attrs[NLMSGERR_ATTR_MSG] + 1);
            msg += " (";
            msg += std::to_string(err_attrs[NLMSGERR_ATTR_MSG]->nla_len);
            msg += " bytes)";
          }
          if (err_attrs[NLMSGERR_ATTR_OFFS]) {
            msg += " error offset: ";
            msg += std::to_string(
                *(uint32_t *)(err_attrs[NLMSGERR_ATTR_OFFS] + 1));
          }
        }

        if (buf_iter != end) {

          status() += "Netlink error had " + std::to_string(end - buf_iter) +
                      " extra bytes at the end (header says " +
                      std::to_string(hdr->nlmsg_len) +
                      "B, flags=" + f("%x", hdr->nlmsg_flags) + ")";
        }

        errno = -err;
        status() += msg;

        return;
      } else if (hdr->nlmsg_type == NLMSG_DONE) {
        return;
      } else {
        void *msg = buf_iter;
        buf_iter += fixed_message_size;
        const uint32_t attribute_max = AttributeMax(protocol, *hdr);
        if (attribute_max == -1) {
          status() += "Unknown netlink message NETLINK_<PROTOCOL>=" +
                      std::to_string(protocol) +
                      " nlmsg_type=" + std::to_string(hdr->nlmsg_type);
          return;
        }

        Attr *attrs[attribute_max + 1];
        memset(attrs, 0, sizeof(attrs));
        int attrs_size = hdr->nlmsg_len - sizeof(nlmsghdr) - fixed_message_size;

        uint32_t i = 0;
        while (i < attrs_size - sizeof(Attr)) {
          i = NLA_ALIGN(i);
          Attr *a = (Attr *)(buf_iter + i);
          if (a->type > attribute_max) {
            status() += "Attribute type " + std::to_string(a->type) +
                        " is out of range";
            return;
          }
          if (a->len < sizeof(Attr)) { // Detect parsing errors early
            status() +=
                "Attribute length " + std::to_string(a->len) + " is too small";
            return;
          }
          attrs[a->type] = a;
          i += a->len;
        }

        if (i != attrs_size) {
          status() += f("i = %d, attr_size = %d", i, attrs_size);
          return; // Parsing error - don't progress further to avoid more noise
        }

        buf_iter += attrs_size;

        if ((hdr->nlmsg_flags & NLM_F_MULTI) == 0) {
          expect_more_messages = false;
        }

        callback(hdr->nlmsg_type, msg, attrs);
      }
    } // while (buf_iter < buf_end - sizeof(nlmsghdr))

    if (buf_iter != buf_end) {
      status() +=
          "Extra data at the end of netlink recv buffer. Message type is " +
          f("0x%x", ((nlmsghdr *)buf)->nlmsg_type) + ".";
      return; // Parsing error - don't progress further to avoid more noise
    }
  } // while (expect_more_messages)
}

} // namespace maf