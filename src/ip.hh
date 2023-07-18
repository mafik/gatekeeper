#pragma once

#include <arpa/inet.h>
#include <bit>

#include "int.hh"
#include "status.hh"
#include "str.hh"

namespace maf {

union __attribute__((__packed__)) IP {
  U32 addr; // network byte order
  U8 bytes[4];
  U16 halves[2];
  IP() : addr(0) {}
  IP(U8 a, U8 b, U8 c, U8 d) : bytes{a, b, c, d} {}
  // Constructor for address in network byte order
  constexpr IP(U32 addr) : addr(addr) {}
  static IP FromInterface(std::string_view interface_name, Status &status);
  static IP NetmaskFromInterface(std::string_view interface_name,
                                 Status &status);
  static IP NetmaskFromPrefixLength(int prefix_length);
  Str to_string() const;
  Str LoggableString() const { return to_string(); }
  auto operator<=>(const IP &other) const {
    return (int32_t)ntohl(addr) <=> (int32_t)ntohl(other.addr);
  }
  bool operator==(const IP &other) const { return addr == other.addr; }
  bool operator!=(const IP &other) const { return addr != other.addr; }
  IP operator&(const IP &other) const { return IP(addr & other.addr); }
  IP operator|(const IP &other) const { return IP(addr | other.addr); }
  IP operator~() const { return IP(~addr); }
  IP operator+(int n) const { return IP(htonl(ntohl(addr) + n)); }
  IP &operator++() {
    addr = htonl(ntohl(addr) + 1);
    return *this;
  }
  bool TryParse(const char *cp) { return inet_pton(AF_INET, cp, &addr) == 1; }
};

struct Network {
  IP ip;
  IP netmask;
  IP BroadcastIP() const { return ip | ~netmask; }
  bool Contains(IP ip) const { return (ip & netmask) == this->ip; }
  int Ones() const { return std::popcount(netmask.addr); }
  int Zeros() const { return 32 - Ones(); }
  Str LoggableString() const;
};

} // namespace maf