#include <cstdint>
#include <functional>
#include <string>

#include "ip.hh"
#include "status.hh"

struct Interface {
  std::string name;
  uint32_t index;

  bool IsLoopback();
  bool IsWireless();
  IP IP(Status &status);
  ::IP Netmask(Status &status);
  Network Network(Status &status);
  void Configure(::Network network, Status &status);
  void Deconfigure(Status &status);
};

void ForEachInetrface(std::function<void(Interface &)> callback);
