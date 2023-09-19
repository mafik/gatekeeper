#include "netfilter.hh"
#include "optional.hh"

#include <cstring>
#include <endian.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>

namespace maf::netfilter {

// Structs used as templates for netlink communication.
namespace messages {

struct BatchBegin : nlmsghdr {
  BatchBegin()
      : nlmsghdr({
            .nlmsg_len = sizeof(*this),
            .nlmsg_type = NFNL_MSG_BATCH_BEGIN,
            .nlmsg_flags = NLM_F_REQUEST,
            .nlmsg_seq = 0,
        }) {}
  nfgenmsg msg{.nfgen_family = AF_UNSPEC,
               .version = NFNETLINK_V0,
               .res_id = NFNL_SUBSYS_NFTABLES};
};

struct BatchEnd : nlmsghdr {
  BatchEnd()
      : nlmsghdr({
            .nlmsg_len = sizeof(*this),
            .nlmsg_type = NFNL_MSG_BATCH_END,
            .nlmsg_flags = NLM_F_REQUEST,
            .nlmsg_seq = 0,
        }) {}
  nfgenmsg msg{.nfgen_family = AF_UNSPEC,
               .version = NFNETLINK_V0,
               .res_id = NFNL_SUBSYS_NFTABLES};
};

} // namespace messages

using namespace messages;

void NewTable(Netlink &netlink, Family family, const char *name,
              Status &status) {
  {
    // Calculate the size of the buffer.
    const size_t name_len = strlen(name) + 1;
    uint32_t buffer_size = 0;
    uint32_t prefix_size = sizeof(BatchBegin);
    buffer_size += prefix_size;
    buffer_size = NLA_ALIGN(buffer_size);
    uint32_t message_size =
        sizeof(nlmsghdr) + sizeof(nfgenmsg) + sizeof(nlattr) + name_len;
    buffer_size += message_size;
    buffer_size = NLA_ALIGN(buffer_size);
    uint32_t suffix_size = sizeof(BatchEnd);
    buffer_size += suffix_size;
    // Fill buffer with data.
    char buffer[buffer_size];
    char *ptr = buffer;
    new (ptr) BatchBegin();
    ptr += NLA_ALIGN(prefix_size);
    new (ptr) nlmsghdr{
        .nlmsg_len = message_size,
        .nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE,
        .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
        .nlmsg_seq = netlink.seq++,
    };
    ptr += sizeof(nlmsghdr);
    new (ptr) nfgenmsg{.nfgen_family = (uint8_t)family,
                       .version = NFNETLINK_V0,
                       .res_id = htons(0)};
    ptr += sizeof(nfgenmsg);
    new (ptr) nlattr{
        .nla_len = (uint16_t)(sizeof(nlattr) + name_len),
        .nla_type = NFTA_TABLE_NAME,
    };
    ptr += sizeof(nlattr);
    memcpy(ptr, name, name_len);
    ptr += NLA_ALIGN(name_len);
    new (ptr) BatchEnd();
    // Send buffer.
    netlink.SendRaw(std::string_view(buffer, buffer_size), status);
  }
  if (!status.Ok())
    goto err;
  netlink.ReceiveAck(status);
  if (!status.Ok())
    goto err;
  return;
err:
  status() += "Couldn't create Netfilter table \"" + std::string(name) + "\")";
}

void DelTable(Netlink &netlink, Family family, const char *name,
              Status &status) {
  {
    // Calculate the size of the buffer.
    const size_t name_len = strlen(name) + 1;
    uint32_t buffer_size = 0;
    uint32_t prefix_size = sizeof(BatchBegin);
    buffer_size += prefix_size;
    buffer_size = NLA_ALIGN(buffer_size);
    uint32_t message_size =
        sizeof(nlmsghdr) + sizeof(nfgenmsg) + sizeof(nlattr) + name_len;
    buffer_size += message_size;
    buffer_size = NLA_ALIGN(buffer_size);
    uint32_t suffix_size = sizeof(BatchEnd);
    buffer_size += suffix_size;
    // Fill buffer with data.
    uint8_t buffer[buffer_size];
    uint8_t *ptr = buffer;
    new (ptr) BatchBegin();
    ptr += NLA_ALIGN(prefix_size);
    new (ptr) nlmsghdr{
        .nlmsg_len = message_size,
        .nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELTABLE,
        .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
        .nlmsg_seq = netlink.seq++,
    };
    ptr += sizeof(nlmsghdr);
    new (ptr) nfgenmsg{.nfgen_family = (uint8_t)family,
                       .version = NFNETLINK_V0,
                       .res_id = htons(0)};
    ptr += sizeof(nfgenmsg);
    new (ptr) nlattr{
        .nla_len = (uint16_t)(sizeof(nlattr) + name_len),
        .nla_type = NFTA_TABLE_NAME,
    };
    ptr += sizeof(nlattr);
    memcpy(ptr, name, name_len);
    ptr += NLA_ALIGN(name_len);
    new (ptr) BatchEnd();
    // Send buffer.
    netlink.SendRaw(std::string_view((const char *)buffer, buffer_size),
                    status);
  }
  if (!status.Ok())
    goto err;
  netlink.ReceiveAck(status);
  if (!status.Ok())
    goto err;
  return;
err:
  status() += "Couldn't delete Netfilter table \"" + std::string(name) + "\"";
}

void NewChain(Netlink &netlink, Family family, const char *table_name,
              const char *chain_name,
              Optional<std::pair<Hook, int32_t>> hook_priority,
              Optional<bool> policy_accept, Status &status) {
  {
    // Calculate the size of the buffer.
    const size_t table_name_len = strlen(table_name) + 1;
    const size_t chain_name_len = strlen(chain_name) + 1;
    uint32_t buffer_size = 0;
    buffer_size += sizeof(BatchBegin);
    const uint32_t message_start = buffer_size;
    buffer_size += sizeof(nlmsghdr);
    buffer_size += sizeof(nfgenmsg);
    buffer_size += sizeof(nlattr); // NFTA_TABLE_NAME
    buffer_size += NLA_ALIGN(table_name_len);
    buffer_size += sizeof(nlattr); // NFTA_CHAIN_NAME
    buffer_size += NLA_ALIGN(chain_name_len);
    const uint32_t hook_start = buffer_size;
    if (hook_priority.has_value()) {
      buffer_size += sizeof(nlattr); // NFTA_CHAIN_HOOK (nested)
      buffer_size += sizeof(nlattr); // NFTA_HOOK_HOOKNUM
      buffer_size += sizeof(uint32_t);
      buffer_size += sizeof(nlattr); // NFTA_HOOK_PRIORITY
      buffer_size += sizeof(int32_t);
    }
    const uint32_t hook_end = buffer_size;
    if (policy_accept.has_value()) {
      buffer_size += sizeof(nlattr); // NFTA_CHAIN_POLICY
      buffer_size += sizeof(uint32_t);
    }
    const uint32_t message_end = buffer_size;
    buffer_size += sizeof(BatchEnd);
    char buffer[buffer_size];
    char *ptr = buffer;
    new (ptr) BatchBegin();
    ptr += sizeof(BatchBegin);
    new (ptr) nlmsghdr{
        .nlmsg_len = message_end - message_start,
        .nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN,
        .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        .nlmsg_seq = netlink.seq++,
    };
    ptr += sizeof(nlmsghdr);
    new (ptr) nfgenmsg{.nfgen_family = (uint8_t)family};
    ptr += sizeof(nfgenmsg);
    new (ptr) nlattr{
        .nla_len = (uint16_t)(sizeof(nlattr) + table_name_len),
        .nla_type = NFTA_TABLE_NAME,
    };
    ptr += sizeof(nlattr);
    memcpy(ptr, table_name, table_name_len);
    ptr += NLA_ALIGN(table_name_len);
    new (ptr) nlattr{
        .nla_len = (uint16_t)(sizeof(nlattr) + chain_name_len),
        .nla_type = NFTA_CHAIN_NAME,
    };
    ptr += sizeof(nlattr);
    memcpy(ptr, chain_name, chain_name_len);
    ptr += NLA_ALIGN(chain_name_len);
    if (hook_priority.has_value()) {
      new (ptr) nlattr{
          .nla_len = (uint16_t)(hook_end - hook_start),
          .nla_type = NFTA_CHAIN_HOOK | NLA_F_NESTED,
      };
      ptr += sizeof(nlattr);
      new (ptr) nlattr{
          .nla_len = (uint16_t)(sizeof(nlattr) + sizeof(uint32_t)),
          .nla_type = NFTA_HOOK_HOOKNUM,
      };
      ptr += sizeof(nlattr);
      *(uint32_t *)ptr = htobe32((uint32_t)hook_priority->first);
      ptr += sizeof(uint32_t);
      new (ptr) nlattr{
          .nla_len = (uint16_t)(sizeof(nlattr) + sizeof(uint32_t)),
          .nla_type = NFTA_HOOK_PRIORITY,
      };
      ptr += sizeof(nlattr);
      *(int32_t *)ptr = htobe32(hook_priority->second);
      ptr += sizeof(uint32_t);
    }
    if (policy_accept.has_value()) {
      new (ptr) nlattr{
          .nla_len = (uint16_t)(sizeof(nlattr) + sizeof(uint32_t)),
          .nla_type = NFTA_CHAIN_POLICY,
      };
      ptr += sizeof(nlattr);
      uint32_t policy_accept_little_endian = policy_accept.value();
      *(uint32_t *)ptr = htobe32(policy_accept_little_endian);
      ptr += sizeof(uint32_t);
    }
    new (ptr) BatchEnd();
    netlink.SendRaw(std::string_view((const char *)buffer, buffer_size),
                    status);
  }
  if (!status.Ok())
    goto err;
  netlink.ReceiveAck(status);
  if (!status.Ok())
    goto err;
  return;
err:
  status() += "Couldn't create chain \"" + std::string(chain_name) +
              "\" in table \"" + std::string(table_name) + "\"";
}

void NewRule(Netlink &netlink, Family family, const char *table_name,
             const char *chain_name, std::string_view rule, Status &status) {
  {
    const size_t table_name_len = strlen(table_name) + 1;
    const size_t chain_name_len = strlen(chain_name) + 1;
    uint32_t buffer_size = 0;
    buffer_size += sizeof(BatchBegin);
    uint32_t message_start = buffer_size;
    buffer_size += sizeof(nlmsghdr);
    buffer_size += sizeof(nfgenmsg);
    buffer_size += sizeof(nlattr); // NFTA_RULE_TABLE
    buffer_size += NLA_ALIGN(table_name_len);
    buffer_size += sizeof(nlattr); // NFTA_RULE_CHAIN
    buffer_size += NLA_ALIGN(chain_name_len);
    buffer_size += sizeof(nlattr); // NFTA_RULE_EXPRESSIONS (nested)
    buffer_size += NLA_ALIGN(rule.size());
    uint32_t message_end = buffer_size;
    buffer_size += sizeof(BatchEnd);
    char buffer[buffer_size];
    char *ptr = buffer;
    new (ptr) BatchBegin();
    ptr += sizeof(BatchBegin);
    new (ptr) nlmsghdr{
        .nlmsg_len = message_end - message_start,
        .nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
        .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
        .nlmsg_seq = netlink.seq++,
    };
    ptr += sizeof(nlmsghdr);
    new (ptr) nfgenmsg{.nfgen_family = (uint8_t)family};
    ptr += sizeof(nfgenmsg);
    new (ptr) nlattr{
        .nla_len = (uint16_t)(sizeof(nlattr) + table_name_len),
        .nla_type = NFTA_RULE_TABLE,
    };
    ptr += sizeof(nlattr);
    memcpy(ptr, table_name, table_name_len);
    ptr += NLA_ALIGN(table_name_len);
    new (ptr) nlattr{
        .nla_len = (uint16_t)(sizeof(nlattr) + chain_name_len),
        .nla_type = NFTA_RULE_CHAIN,
    };
    ptr += sizeof(nlattr);
    memcpy(ptr, chain_name, chain_name_len);
    ptr += NLA_ALIGN(chain_name_len);
    new (ptr) nlattr{
        .nla_len = (uint16_t)(sizeof(nlattr) + rule.size()),
        .nla_type = NFTA_RULE_EXPRESSIONS | NLA_F_NESTED,
    };
    ptr += sizeof(nlattr);
    memcpy(ptr, rule.data(), rule.size());
    ptr += NLA_ALIGN(rule.size());
    new (ptr) BatchEnd();
    netlink.SendRaw(std::string_view((const char *)buffer, buffer_size),
                    status);
  }
  if (!status.Ok())
    goto err;
  netlink.ReceiveAck(status);
  if (!status.Ok())
    goto err;
  return;
err:
  status() += "Couldn't create a new rule in table \"" +
              std::string(table_name) + "\" chain \"" +
              std::string(chain_name) + "\"";
}

} // namespace maf::netfilter
