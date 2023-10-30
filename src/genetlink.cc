#include "genetlink.hh"

#include <cstring>
#include <linux/genetlink.h>

#include "format.hh"
#include "hex.hh"
#include "log.hh"
#include "status.hh"
#include "str.hh"

namespace maf {

static void SendGetFamily(Netlink &nl, StrView family, Status &status) {
  struct GetFamily {
    nlmsghdr hdr{
        .nlmsg_len = sizeof(GetFamily),
        .nlmsg_type = GENL_ID_CTRL,
        .nlmsg_flags = NLM_F_REQUEST,
        .nlmsg_seq = 0, // Populated by Netlink::Send
        .nlmsg_pid = 0,
    };
    genlmsghdr genl{
        .cmd = CTRL_CMD_GETFAMILY,
        .version = 2,
    };
    nlattr attr{
        .nla_len = sizeof(attr),
        .nla_type = CTRL_ATTR_FAMILY_NAME,
    };
    char family[];
  };

  U32 len = NLMSG_ALIGN(sizeof(GetFamily) + family.size() + 1);
  alignas(GetFamily) U8 buf[len];
  GetFamily *get_family = new (buf) GetFamily();
  get_family->hdr.nlmsg_len = len;
  get_family->attr.nla_len = (U16)(sizeof(nlattr) + family.size() + 1);
  memcpy(get_family->family, family.data(), family.size());
  get_family->family[family.size()] = '\0';

  // LOG << HexDump(StrView((char *)buf, len));

  nl.Send(get_family->hdr, status);
  if (!OK(status)) {
    AppendErrorMessage(status) += "Couldn't send GETFAMILY message";
    return;
  }
}

Str GenericNetlink::Cmd::LoggableString() const {
  Str ret = f("Cmd(%u", op_id);
  if (flags & GENL_CMD_CAP_DO) {
    ret += ", DO";
  }
  if (flags & GENL_CMD_CAP_DUMP) {
    ret += ", DUMP";
  }
  ret += ")";
  return ret;
}

GenericNetlink::GenericNetlink(StrView family, int cmd_max, Status &status)
    : netlink(NETLINK_GENERIC, status), family(family) {
  if (!OK(status)) {
    AppendErrorMessage(status) +=
        "Netlink couldn't establish connection to kernel. Maybe the kernel is "
        "missing netlink support?";
    return;
  }

  SendGetFamily(netlink, family, status);
  if (!OK(status)) {
    AppendErrorMessage(status) += "Couldn't send GETFAMILY message";
    return;
  }

  cmds.resize(cmd_max + 1);

  netlink.ReceiveT<genlmsghdr>(
      GENL_ID_CTRL,
      [this](genlmsghdr &genl, Netlink::Attrs attrs) {
        for (auto &attr : attrs) {
          switch (attr.type) {
          case CTRL_ATTR_FAMILY_ID:
            family_id = attr.As<U16>();
            break;
          case CTRL_ATTR_VERSION:
            family_version = attr.As<U32>();
            break;
          case CTRL_ATTR_HDRSIZE:
            header_size = attr.As<U32>();
            break;
          case CTRL_ATTR_MAXATTR:
            max_attrs = attr.As<U32>();
            break;
          case CTRL_ATTR_OPS: {
            Span<> view = attr.Span();
            while (!view.empty()) {
              U16 len = *(U16 *)view.data();
              U16 index = *(U16 *)(view.data() + 2);
              U32 op_id = 0;
              U32 op_flags = 0;
              Span<> op_attrs = view.subspan(4, len - 4);
              while (!op_attrs.empty()) {
                U16 attr_len = *(U16 *)op_attrs.data();
                U16 attr_type = *(U16 *)(op_attrs.data() + 2);
                switch (attr_type) {
                case CTRL_ATTR_OP_ID:
                  op_id = *(U32 *)(op_attrs.data() + 4);
                  break;
                case CTRL_ATTR_OP_FLAGS:
                  op_flags = *(U32 *)(op_attrs.data() + 4);
                  break;
                }
                op_attrs.RemovePrefix(attr_len);
              }
              if (op_id < cmds.size()) {
                cmds[op_id] = {
                    .op_id = op_id, .index = index, .flags = op_flags};
              }
              view.RemovePrefix(len);
            }
            break;
          }
          default:
            break;
          }
        }
      },
      status);
  if (!OK(status)) {
    AppendErrorMessage(status) += "Couldn't receive GETFAMILY response";
    return;
  }
}

void GenericNetlink::Dump(U8 cmd, Netlink::Attr *attr,
                          Fn<void(Span<>, Netlink::Attrs)> cb, Status &status) {
  struct Message {
    nlmsghdr hdr;
    genlmsghdr genl;
  } msg{
      .hdr =
          {
              .nlmsg_len = sizeof(Message),
              .nlmsg_type = family_id,
              .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
              .nlmsg_seq = 0, // Populated by Netlink::Send
              .nlmsg_pid = 0,
          },
      .genl =
          {
              .cmd = cmd,
              .version = 0,
          },
  };
  if (attr == nullptr) {
    netlink.Send(msg.hdr, status);
  } else {
    netlink.SendWithAttr(msg.hdr, *attr, status);
  }
  if (!OK(status)) {
    AppendErrorMessage(status) += "Couldn't send netlink message";
    return;
  }

  netlink.ReceiveT<genlmsghdr>(
      family_id,
      [&](genlmsghdr &genl, Netlink::Attrs attrs) {
        Span<> header(attrs.ptr, header_size);
        attrs.ptr += NLA_ALIGN(header_size);
        attrs.size -= NLA_ALIGN(header_size);
        cb(header, attrs);
      },
      status);
}

} // namespace maf