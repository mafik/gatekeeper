#pragma once

#include "fn.hh"
#include "ip.hh"
#include "mac.hh"

#include <chrono>
#include <map>

namespace gatekeeper {

struct TrafficBytes {
  automat::U32 up = 0;
  automat::U32 down = 0;
};

struct TrafficLog {
  automat::MAC local_host;
  automat::IP remote_ip;
  mutable std::map<std::chrono::system_clock::time_point, TrafficBytes> entries;
  static void Init();
};

void RecordTraffic(automat::MAC local_host, automat::IP remote_ip,
                   automat::U32 up, automat::U32 down);

void QueryTraffic(automat::Fn<void(const TrafficLog &)> callback);

} // namespace gatekeeper