#pragma once

// Functions for working with Generic Netlink.
//
// This module contains only the generic netlink layer. Specific netlink
// families should be implemented on top of it.

#include "fn.hh"
#include "netlink.hh"
#include "status.hh"
#include "str.hh"
#include "vec.hh"

namespace maf {

struct GenericNetlink {
  using Command = U8;
  using Attrs = Netlink::Attrs;
  using Callback = Fn<void(Command, Attrs)>;

  Netlink netlink;
  Str family;
  U16 family_id;
  U32 family_version;
  U32 header_size;
  U32 max_attrs;
  struct Cmd {
    U32 op_id;
    U32 index;
    U32 flags;
  };
  Vec<Cmd> cmds; // maps netlink command to index
  struct MulticastGroup {
    U32 id;
    Str name;
  };
  Vec<MulticastGroup> multicast_groups;
  Callback epoll_callback;

  // Establish connection with the specified generic netlink family.
  GenericNetlink(StrView family, int cmd_max, Status &status);

  void Dump(U8 cmd, Netlink::Attr *attr, Fn<void(Attrs)> cb, Status &status);

  void AddMembership(StrView group_name, Status &status);

  // Receive a message without any fixed-size header.
  void Receive(Callback cb, Status &status);
};

Str ToStr(const GenericNetlink::Cmd &);
static_assert(Stringer<GenericNetlink::Cmd>);

} // namespace maf