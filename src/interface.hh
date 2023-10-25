#pragma once

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
  maf::IP IP(maf::Status &status);
  maf::IP Netmask(maf::Status &status);
  maf::Network Network(maf::Status &status);
  void Configure(maf::IP ip, maf::Network network, maf::Status &status);
  void Deconfigure(maf::Status &status);
  static void CheckName(std::string_view name, maf::Status &status);
};

void ForEachInetrface(std::function<void(Interface &)> callback);
