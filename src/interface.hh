#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "ip.hh"
#include "status.hh"
#include "vec.hh"

struct Interface {
  std::string name = "";
  uint32_t index = 0;

  bool IsLoopback();
  bool IsWireless();
  maf::IP IP(maf::Status &status);
  maf::IP Netmask(maf::Status &status);
  maf::Network Network(maf::Status &status);
  void BringUp(maf::Status &status);
  void BringDown(maf::Status &status);
  void Configure(maf::IP ip, maf::Network network, maf::Status &status);
  void Deconfigure(maf::Status &status);

  // Update the index of the interface based on its name.
  void UpdateIndex(maf::Status &status);

  static void CheckName(std::string_view name, maf::Status &status);
};

void ForEachInetrface(std::function<void(Interface &)> callback);

Interface BridgeInterfaces(const maf::Vec<Interface> &interfaces,
                           const char *bridge_name, maf::Status &status);

void DeleteBridge(const char *bridge_name, maf::Status &status);