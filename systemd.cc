#include "systemd.hh"

#include <systemd/sd-daemon.h>

#include "log.hh"

namespace systemd {
void NotifyReady() { sd_notify(0, "READY=1"); }

static void LogErrorAsStatus(const LogEntry &log_entry) {
  if (log_entry.log_level >= LogLevel::Error) {
    sd_notifyf(0, "STATUS=%s\nERRNO=%i", log_entry.buffer.c_str(),
               log_entry.errsv);
  }
}

void PublishErrorsAsStatus() { loggers.push_back(LogErrorAsStatus); }
} // namespace systemd