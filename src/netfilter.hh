#pragma once

#include <cstdint>

#include "netlink.hh"
#include "status.hh"

// Utilities for interacting with the Linux Netfilter framework.
//
// See https://en.wikipedia.org/wiki/Netfilter.
namespace maf::netfilter {

enum class Family : uint8_t {
  UNSPEC = 0,
  IPv4 = 2,
};

enum class Hook {
  PRE_ROUTING,
  LOCAL_IN,
  FORWARD,
  LOCAL_OUT,
  POST_ROUTING,
};

// Create a new nftables table.
void NewTable(Netlink &netlink, Family family, const char *name,
              Status &status);

// Delete an existing nftables table.
void DelTable(Netlink &netlink, Family family, const char *name,
              Status &status);

// Create a new nftables chain.
void NewChain(Netlink &netlink, Family family, const char *table_name,
              const char *chain_name, Hook hook, int32_t priority,
              Status &status);

// Create a new nftables rule.
//
// This library doesn't include code to construct `rule` bytecode but they can
// be sniffed by running the official `nft` command under `strace`:
//
//   strace -s 9999 -e trace=sendmsg nft add rule <table> <chain> <expression>
//
// The string can then be taken from the long string that starts after
// "nla_type=NLA_F_NESTED|0x4".
//
// Specific values within the string can be identified by placing sentinel
// values in the <expression> passed to `nft` and observing contents of the
// generated buffer. It may also be usefull to diff a couple invocations with
// different values to see where they're located.
void NewRule(Netlink &netlink, Family family, const char *table_name,
             const char *chain_name, std::string_view rule, Status &status);

} // namespace maf::netfilter