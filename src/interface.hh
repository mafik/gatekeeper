#pragma once

#include <functional>
#include <string>

#include "ip.hh"
#include "status.hh"
#include "vec.hh"

namespace maf {

struct Interface {
  std::string name = "";
  U32 index = 0;

  bool IsLoopback();
  bool IsWireless();
  maf::IP IP(Status &);
  maf::IP Netmask(Status &);
  Network Network(Status &);
  void BringUp(Status &) const;
  void BringDown(Status &) const;
  void Configure(maf::IP, maf::Network, Status &);
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

} // namespace maf