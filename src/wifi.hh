#pragma once

#include "interface.hh"
#include "nl80211.hh"
#include "status.hh"

namespace automat::wifi {

enum class Band {
  kPrefer2GHz,
  kPrefer5GHz,
};

struct AccessPoint {
  nl80211::Netlink netlink;
  nl80211::Interface iface;
  Arr<char, 16> gtk;
  Arr<char, 32> psk;

  AccessPoint(const Interface &, Band, StrView ssid, StrView password,
              Status &);

  ~AccessPoint();
};

} // namespace automat::wifi