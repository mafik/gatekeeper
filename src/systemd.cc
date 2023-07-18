#include "systemd.hh"

#include <optional>
#include <sys/types.h>
#include <systemd/sd-daemon.h>

#include "log.hh"
#include "timer.hh"

using namespace maf;

namespace systemd {

void NotifyReady() { sd_notify(0, "READY=1"); }

static void LogErrorAsStatus(const LogEntry &log_entry) {
  if (log_entry.log_level >= LogLevel::Error) {
    sd_notifyf(0, "STATUS=%s\nERRNO=%i", log_entry.buffer.c_str(),
               log_entry.errsv);
  }
}

void PublishErrorsAsStatus() { loggers.push_back(LogErrorAsStatus); }

std::optional<Timer> watchdog_timer;

void StartWatchdog() {
  uint64_t usec;
  if (sd_watchdog_enabled(0, &usec)) {
    double interval_s = usec / 2.0 / 1000000.0;
    watchdog_timer.emplace();
    watchdog_timer->handler = []() { sd_notify(0, "WATCHDOG=1"); };
    watchdog_timer->Arm(interval_s, interval_s);
  }
}

void StopWatchdog() { watchdog_timer.reset(); }

} // namespace systemd