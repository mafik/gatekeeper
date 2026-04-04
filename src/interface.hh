#pragma once

#include <functional>
#include <string>

#include "ip.hh"
#include "status.hh"
#include "vec.hh"

namespace automat {

struct Interface {
  std::string name = "";
  U32 index = 0;

  bool IsLoopback();
  bool IsWireless();
  automat::IP IP(Status &);
  automat::IP Netmask(Status &);
  Network Network(Status &);
  void BringUp(Status &) const;
  void BringDown(Status &) const;
  void Configure(automat::IP, automat::Network, Status &);
  void Deconfigure(Status &);
  void EnableForwarding(Status &);

  // Update the index of the interface based on its name.
  void UpdateIndex(Status &);

  static void CheckName(std::string_view name, Status &);
};

void ForEachInetrface(std::function<void(Interface &)> callback);

Interface BridgeInterfaces(const Vec<Interface> &interfaces,
                           const char *bridge_name, Status &status);

void DeleteBridge(const char *bridge_name, Status &status);

} // namespace automat