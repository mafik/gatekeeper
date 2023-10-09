#include "traffic_log.hh"

#include <chrono>
#include <set>

using namespace maf;
using namespace std;

namespace gatekeeper {

struct TrafficEndpoints {
  MAC local_host;
  maf::IP remote_ip;
};

struct OrderByHosts {
  using is_transparent = std::true_type;

  bool operator()(const TrafficEndpoints &a, const TrafficLog *b) const {
    if (a.local_host <=> b->local_host == 0)
      return a.remote_ip < b->remote_ip;
    return a.local_host < b->local_host;
  }

  bool operator()(const TrafficLog *a, const TrafficEndpoints &b) const {
    if (a->local_host <=> b.local_host == 0)
      return a->remote_ip < b.remote_ip;
    return a->local_host < b.local_host;
  }

  bool operator()(const TrafficLog *a, const TrafficLog *b) const {
    if (a->local_host <=> b->local_host == 0)
      return a->remote_ip < b->remote_ip;
    return a->local_host < b->local_host;
  }
};

struct OrderByOldestEntry {
  using is_transparent = std::true_type;

  bool operator()(const chrono::steady_clock::time_point a,
                  const TrafficLog *b) const {
    return a < b->entries.begin()->first;
  }
  bool operator()(const TrafficLog *a, const TrafficLog *b) const {
    return a->entries.begin()->first < b->entries.begin()->first;
  }
};

mutex traffic_logs_mutex;

set<TrafficLog *, OrderByHosts> traffic_logs;
multiset<TrafficLog *, OrderByOldestEntry> traffic_log_expiration_queue;

void RecordTraffic(MAC local_host, maf::IP remote_ip, maf::U32 up,
                   maf::U32 down) {
  lock_guard lock(traffic_logs_mutex);
  auto now = chrono::steady_clock::now();
  // Limit resolution of traffic logs to 0.1 second
  now -= chrono::duration_cast<chrono::steady_clock::duration>(
             now.time_since_epoch()) %
         100ms;
  auto it = traffic_logs.find<TrafficEndpoints>({local_host, remote_ip});
  if (it == traffic_logs.end()) {
    auto *log = new TrafficLog{local_host, remote_ip, {{now, {up, down}}}};
    traffic_logs.insert(log);
    traffic_log_expiration_queue.insert(log);
  } else {
    auto &e = (*it)->entries[now];
    e.up += up;
    e.down += down;
  }
  // Expire old logs.
  auto expiration = now - 24h;
  while (!traffic_log_expiration_queue.empty()) {
    // Grab the oldest TrafficLog.
    auto it = traffic_log_expiration_queue.begin();
    auto *log = *it;
    // Find the oldest entry in the log that is still valid.
    auto expired_last = log->entries.upper_bound(expiration);
    if (expired_last == log->entries.begin()) {
      // All entries are valid. Nothing more to expire.
      break;
    } else if (expired_last == log->entries.end()) {
      // There are no entries left. Delete this log.
      traffic_log_expiration_queue.erase(it);
      traffic_logs.erase(log);
      delete log;
    } else {
      // There are still some entries left. Reinsert the log.
      traffic_log_expiration_queue.erase(it);
      log->entries.erase(log->entries.begin(), expired_last);
      traffic_log_expiration_queue.insert(log);
    }
  }
}

void QueryTraffic(maf::Fn<void(const TrafficLog &)> callback) {
  lock_guard lock(traffic_logs_mutex);
  for (const auto &log : traffic_logs) {
    callback(*log);
  }
}

} // namespace gatekeeper