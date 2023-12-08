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
  maf::IP IP(Status &status);
  maf::IP Netmask(Status &status);
  Network Network(Status &status);
  void BringUp(Status &status) const;
  void BringDown(Status &status) const;
  void Configure(maf::IP ip, maf::Network network, Status &status);
  void Deconfigure(Status &status);

  // Update the index of the interface based on its name.
  void UpdateIndex(Status &status);

  static void CheckName(std::string_view name, Status &status);
};

void ForEachInetrface(std::function<void(Interface &)> callback);

Interface BridgeInterfaces(const Vec<Interface> &interfaces,
                           const char *bridge_name, Status &status);

void DeleteBridge(const char *bridge_name, Status &status);

} // namespace maf