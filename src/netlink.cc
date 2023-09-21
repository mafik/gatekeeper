#include "netlink.hh"
#include "format.hh"

#include <cstring>
#include <linux/inet_diag.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
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
  case NETLINK_SOCK_DIAG:
    return INET_DIAG_MAX;
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
  case NETLINK_SOCK_DIAG:
    fixed_message_size = sizeof(inet_diag_msg);
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

void Netlink::ReceiveAck(Status &status) {
  Receive(NLMSG_ERROR, nullptr, status);
}

void Netlink::Receive(uint16_t expected_type, ReceiveCallback callback,
                      Status &status) {
  bool expect_more_messages = true;
  while (expect_more_messages) {
    ssize_t peek_len = recv(fd, nullptr, 0, MSG_PEEK | MSG_TRUNC);
    if (peek_len < 0) {
      status() += "recv(AF_NETLINK, MSG_PEEK)";
      return;
    }
    char buf[peek_len];
    ssize_t len = recv(fd, buf, sizeof(buf), 0);
    if (len < 0) {
      status() += "recv(AF_NETLINK)";
      return;
    }

    char *buf_iter = buf;
    char *buf_end = buf + len;

    while (buf_iter < buf_end - sizeof(nlmsghdr)) {
      buf_iter = (char *)(((uintptr_t)buf_iter + 3) & ~3); // align to 4 bytes

      nlmsghdr *hdr = (nlmsghdr *)(buf_iter);
      char *msg_end = buf_iter + hdr->nlmsg_len;
      if (msg_end > buf_end) {
        status() += "Truncated Netlink message, msg_len=" +
                    std::to_string(hdr->nlmsg_len) +
                    ", buf_size=" + std::to_string(len);
        return;
      }
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
        if (hdr->nlmsg_type != expected_type) {
          status() +=
              f("Received wrong netlink message expected type=%x, got type=%x",
                expected_type, hdr->nlmsg_type);
          return;
        }

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

        while (buf_iter < msg_end - sizeof(Attr)) {
          buf_iter = (char *)(((uintptr_t)buf_iter + 3ull) & ~3ull);
          Attr *a = (Attr *)buf_iter;
          if (a->len < sizeof(Attr)) { // Detect parsing errors early
            status() +=
                "Attribute length " + std::to_string(a->len) + " is too small";
            return;
          }
          if (a->type > attribute_max) {
            // New kernel versions can add new attributes.
            // They should be ignored.
          } else {
            attrs[a->type] = a;
          }
          buf_iter += a->len;
          if (buf_iter > msg_end) {
            status() +=
                "Attribute length " + std::to_string(a->len) + " is too large";
            return;
          }
        }

        if (buf_iter != msg_end) {
          buf_iter = (char *)(((uintptr_t)buf_iter + 3ull) & ~3ull);
          if (buf_iter != msg_end) {
            status() += f("Parsing error (buf_iter=%p, msg_end=%p)",
                          buf_iter - buf, msg_end - buf);
            return; // Parsing error - don't progress further to avoid more
                    // noise
          }
        }

        if ((hdr->nlmsg_flags & NLM_F_MULTI) == 0) {
          expect_more_messages = false;
        }
        callback(msg, {attrs, attribute_max + 1});
      }
    } // while (buf_iter < buf_end - sizeof(nlmsghdr))

    if (buf_iter != buf_end) {
      if (buf_iter < buf_end) {
        status() +=
            "Extra data at the end of netlink recv buffer. Message type is " +
            f("0x%x", ((nlmsghdr *)buf)->nlmsg_type);
      } else {
        status() += "Netlink parsing code overshot the end of buffer by " +
                    std::to_string(buf_iter - buf_end) + " bytes";
      }
      return; // Parsing error - don't progress further to avoid more noise
    }
  } // while (expect_more_messages)
}

} // namespace maf