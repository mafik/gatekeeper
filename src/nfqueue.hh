#pragma once

#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>

#include "netfilter.hh"

namespace maf::netfilter {

// Number of the nfqueue used to intercept messages.
constexpr Big<U16> kQueueNumber = 1337;

// All netlink structures are manually padded. Any compiler-injected padding
// shold be treated as an error.
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wpadded"

// Message that binds this netlink socket to a specific nfqueue
// (`kQueueNumber`).
struct Bind : nlmsghdr {
  Bind()
      : nlmsghdr({
            .nlmsg_len = sizeof(*this),
            .nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG,
            .nlmsg_flags = NLM_F_REQUEST,
            .nlmsg_seq = 0,
        }) {}
  nfgenmsg msg{.nfgen_family = (U8)Family::UNSPEC,
               .version = NFNETLINK_V0,
               .res_id = kQueueNumber.big_endian};
  nlattr cmd_attr{
      .nla_len = sizeof(cmd_attr) + sizeof(cmd),
      .nla_type = NFQA_CFG_CMD,
  };
  nfqnl_msg_config_cmd cmd{
      .command = NFQNL_CFG_CMD_BIND,
  };
};

// Configure nfqueue to copy the entire packet into userspace.
struct CopyPacket : nlmsghdr {
  CopyPacket()
      : nlmsghdr({
            .nlmsg_len = sizeof(*this),
            .nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG,
            .nlmsg_flags = NLM_F_REQUEST,
            .nlmsg_seq = 0,
        }) {}
  nfgenmsg msg{.nfgen_family = AF_UNSPEC,
               .version = NFNETLINK_V0,
               .res_id = kQueueNumber.big_endian};
  nlattr params_attr{
      .nla_len = sizeof(params_attr) + sizeof(params),
      .nla_type = NFQA_CFG_PARAMS,
  };
  nfqnl_msg_config_params params{
      .copy_range = 0xffff,
      .copy_mode = NFQNL_COPY_PACKET,
  };

private:
  char padding_[3]{}; // align nlattr to 4 bytes

public:
  nlattr flags_attr{
      .nla_len = sizeof(flags_attr) + sizeof(flags),
      .nla_type = NFQA_CFG_FLAGS,
  };
  Big<U32> flags = NFQA_CFG_F_GSO;
  nlattr mask_attr{
      .nla_len = sizeof(mask_attr) + sizeof(mask),
      .nla_type = NFQA_CFG_MASK,
  };
  Big<U32> mask = NFQA_CFG_F_GSO;
};

struct Verdict : nlmsghdr {
  static constexpr U32 NF_ACCEPT = 1;
  static constexpr U32 NF_DROP = 0;
  Verdict(U32 packet_id_be32, bool accept)
      : nlmsghdr({
            .nlmsg_len = sizeof(*this),
            .nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT,
            .nlmsg_flags = NLM_F_REQUEST,
            .nlmsg_seq = 0,
        }),
        verdict({
            .verdict = Big<U32>(accept ? NF_ACCEPT : NF_DROP).big_endian,
            .id = packet_id_be32,
        }) {}
  nfgenmsg msg{.nfgen_family = AF_UNSPEC,
               .version = NFNETLINK_V0,
               .res_id = kQueueNumber.big_endian};
  nlattr verdict_attr{
      .nla_len = sizeof(verdict_attr) + sizeof(verdict),
      .nla_type = NFQA_VERDICT_HDR,
  };
  nfqnl_msg_verdict_hdr verdict{
      .verdict = Big<U32>(NF_ACCEPT).big_endian,
      .id = 0,
  };
};

#pragma GCC diagnostic pop

} // namespace maf::netfilter