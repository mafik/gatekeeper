#include "netlink.hh"
#include "format.hh"

#include <cassert>
#include <cstring>
#include <linux/netlink.h>
#include <string>

namespace maf {

static constexpr sockaddr_nl kKernelSockaddr{
    .nl_family = AF_NETLINK,
    .nl_pid = 0,
    .nl_groups = 0,
};

Netlink::Netlink(int protocol) {
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

bool Netlink::Ok() { return status.Ok(); }

void Netlink::Send(nlmsghdr &msg, Status *status_arg) {
  msg.nlmsg_seq = seq++;
  SendRaw(std::string_view((char *)&msg, msg.nlmsg_len), status_arg);
}

void Netlink::SendWithAttr(nlmsghdr &hdr, nlattr &attr, Status *status_arg) {
  Status &out_status = status_arg ? *status_arg : status;
  uint16_t hdr_len = hdr.nlmsg_len;

  hdr.nlmsg_seq = seq++;
  hdr.nlmsg_len += attr.nla_len;

  iovec iov[2] = {
      {
          .iov_base = &hdr,
          .iov_len = hdr_len,
      },
      {
          .iov_base = &attr,
          .iov_len = attr.nla_len,
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
    out_status() += "sendmsg(AF_NETLINK)";
    return;
  }
}

void Netlink::SendRaw(std::string_view raw, Status *status_arg) {
  Status &out_status = status_arg ? *status_arg : status;
  ssize_t len = sendto(fd, raw.data(), raw.size(), 0,
                       (sockaddr *)&kKernelSockaddr, sizeof(kKernelSockaddr));
  if (len < 0) {
    out_status() += "sendto(AF_NETLINK)";
    return;
  }
}

void Netlink::Receive(size_t message_size, int attribute_max,
                      ReceiveCallback callback, Status *status_arg) {
  Status &out_status = status_arg ? *status_arg : status;
  bool expect_more_messages = true;
  while (expect_more_messages) {
    char buf[1024 * 32];
    ssize_t len = recv(fd, buf, sizeof(buf), 0);
    if (len < 0) {
      out_status() += "recv(AF_NETLINK)";
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

          out_status() += "Netlink error had " +
                          std::to_string(end - buf_iter) +
                          " extra bytes at the end (header says " +
                          std::to_string(hdr->nlmsg_len) +
                          "B, flags=" + f("%x", hdr->nlmsg_flags) + ")";
        }

        errno = -err;
        out_status() += msg;

        return;
      } // if NLMSG_ERROR

      if (hdr->nlmsg_type == NLMSG_DONE) {
        return;
      }

      void *msg = buf_iter;
      buf_iter += message_size;

      nlattr *attrs[attribute_max + 1];
      memset(attrs, 0, sizeof(attrs));
      int attr_size = hdr->nlmsg_len - sizeof(nlmsghdr) - message_size;

      uint32_t i = 0;
      while (i < attr_size - sizeof(nlattr)) {
        i = NLA_ALIGN(i);
        nlattr *a = (nlattr *)(buf_iter + i);
        if (a->nla_type > attribute_max) {
          out_status() += "Attribute type " + std::to_string(a->nla_type) +
                          " is out of range";
          return;
        }
        if (a->nla_len < sizeof(nlattr)) {
          out_status() += "Attribute length " + std::to_string(a->nla_len) +
                          " is too small";
          return;
        }
        attrs[a->nla_type] = a;
        i += a->nla_len;
      }

      if (i != attr_size) {
        out_status() += f("i = %d, attr_size = %d", i, attr_size);
        assert(false);
      }

      buf_iter += attr_size;

      if ((hdr->nlmsg_flags & NLM_F_MULTI) == 0) {
        expect_more_messages = false;
      }

      callback(hdr->nlmsg_type, msg, attrs);
    } // while (buf_iter < buf_end - sizeof(nlmsghdr))

    if (buf_iter != buf_end) {
      out_status() += "Extra data at the end of netlink recv buffer";
      assert(false);
    }
  }
}

} // namespace maf