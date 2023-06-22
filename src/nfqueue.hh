#pragma once

#include <cstdint>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>

#include "netfilter.hh"

namespace maf::netfilter {

// Default queue used to initialize messages.
extern thread_local uint16_t default_queue;

// All netlink structures are manually padded. Any compiler-injected padding
// shold be treated as an error.
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wpadded"

struct Bind : nlmsghdr {
  Bind()
      : nlmsghdr({
            .nlmsg_len = sizeof(*this),
            .nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG,
            .nlmsg_flags = NLM_F_REQUEST,
            .nlmsg_seq = 0,
        }) {}
  nfgenmsg msg{.nfgen_family = (uint8_t)Family::UNSPEC,
               .version = NFNETLINK_V0,
               .res_id = htons(default_queue)};
  nlattr cmd_attr{
      .nla_len = sizeof(cmd_attr) + sizeof(cmd),
      .nla_type = NFQA_CFG_CMD,
  };
  nfqnl_msg_config_cmd cmd{
      .command = NFQNL_CFG_CMD_BIND,
  };
};

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
               .res_id = htons(default_queue)};
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
  uint32_t flags = htonl(NFQA_CFG_F_GSO);
  nlattr mask_attr{
      .nla_len = sizeof(mask_attr) + sizeof(mask),
      .nla_type = NFQA_CFG_MASK,
  };
  uint32_t mask = htonl(NFQA_CFG_F_GSO);
};

struct Verdict : nlmsghdr {
  static constexpr uint32_t NF_ACCEPT = 1;
  static constexpr uint32_t NF_DROP = 1;
  Verdict(uint32_t packet_id_be32, bool accept)
      : nlmsghdr({
            .nlmsg_len = sizeof(*this),
            .nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT,
            .nlmsg_flags = NLM_F_REQUEST,
            .nlmsg_seq = 0,
        }),
        verdict({
            .verdict = htonl(accept ? NF_ACCEPT : NF_DROP),
            .id = packet_id_be32,
        }) {}
  nfgenmsg msg{.nfgen_family = AF_UNSPEC,
               .version = NFNETLINK_V0,
               .res_id = htons(default_queue)};
  nlattr verdict_attr{
      .nla_len = sizeof(verdict_attr) + sizeof(verdict),
      .nla_type = NFQA_VERDICT_HDR,
  };
  nfqnl_msg_verdict_hdr verdict{
      .verdict = htonl(NF_ACCEPT),
      .id = 0,
  };
};

#pragma GCC diagnostic pop

} // namespace maf::netfilter