#pragma once

#include <arpa/inet.h>
#include <bit>

#include "big_endian.hh"
#include "int.hh"
#include "status.hh"
#include "str.hh"

namespace maf {

union __attribute__((__packed__)) IP {
  U32 addr; // network byte order
  Big<U32> addr_big_endian;
  U8 bytes[4];
  Big<U16> halves[2];
  IP() : addr(0) {}
  IP(U8 a, U8 b, U8 c, U8 d) : bytes{a, b, c, d} {}
  // Constructor for address in network byte order
  constexpr IP(U32 addr) : addr(addr) {}
  static IP FromInterface(std::string_view interface_name, Status &status);
  static IP NetmaskFromInterface(std::string_view interface_name,
                                 Status &status);
  static IP NetmaskFromPrefixLength(int prefix_length);
  auto operator<=>(const IP &other) const {
    return addr_big_endian <=> other.addr_big_endian;
  }
  bool operator==(const IP &other) const { return addr == other.addr; }
  bool operator!=(const IP &other) const { return addr != other.addr; }
  IP operator&(const IP &other) const { return IP(addr & other.addr); }
  IP operator|(const IP &other) const { return IP(addr | other.addr); }
  IP operator~() const { return IP(~addr); }
  IP operator+(int n) const {
    Big<U32> sum = addr_big_endian.Get() + n;
    return IP(sum.big_endian);
  }
  IP &operator++() {
    addr_big_endian.Set(addr_big_endian.Get() + 1);
    return *this;
  }
  bool TryParse(const char *cp) {
    return sscanf(cp, "%hhu.%hhu.%hhu.%hhu", bytes, bytes + 1, bytes + 2,
                  bytes + 3) == 4;
  }

  const static IP kZero;
};

Str ToStr(IP);
static_assert(Stringer<IP>);

struct Network {
  IP ip;
  IP netmask;
  IP BroadcastIP() const { return ip | ~netmask; }
  bool Contains(IP ip) const { return (ip & netmask) == this->ip; }
  int Ones() const { return std::popcount(netmask.addr); }
  int Zeros() const { return 32 - Ones(); }
};

Str ToStr(const Network &);
static_assert(Stringer<Network>);

} // namespace maf

template <> struct std::hash<maf::IP> {
  std::size_t operator()(const maf::IP &ip) const {
    return std::hash<maf::U32>()(ip.addr);
  }
};