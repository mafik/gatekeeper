#pragma once

#include "fn.hh"
#include "ip.hh"
#include "mac.hh"

#include <chrono>
#include <map>

namespace gatekeeper {

struct TrafficBytes {
  maf::U32 up = 0;
  maf::U32 down = 0;
};

struct TrafficLog {
  MAC local_host;
  maf::IP remote_ip;
  mutable std::map<std::chrono::system_clock::time_point, TrafficBytes> entries;
};

void RecordTraffic(MAC local_host, maf::IP remote_ip, maf::U32 up,
                   maf::U32 down);

void QueryTraffic(maf::Fn<void(const TrafficLog &)> callback);

} // namespace gatekeeper