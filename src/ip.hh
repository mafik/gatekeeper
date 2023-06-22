#pragma once

#include <arpa/inet.h>
#include <bit>
#include <cstdint>
#include <string>
#include <string_view>

#include "status.hh"

union __attribute__((__packed__)) IP {
  uint32_t addr; // network byte order
  uint8_t bytes[4];
  uint16_t halves[2];
  IP() : addr(0) {}
  IP(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    bytes[0] = a;
    bytes[1] = b;
    bytes[2] = c;
    bytes[3] = d;
  }
  // Constructor for address in network byte order
  IP(uint32_t a) : addr(a) {}
  static IP FromInterface(std::string_view interface_name, Status &status);
  static IP NetmaskFromInterface(std::string_view interface_name,
                                 Status &status);
  static IP NetmaskFromPrefixLength(int prefix_length);
  std::string to_string() const;
  std::string LoggableString() const { return to_string(); }
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
  std::string LoggableString() const;
};
