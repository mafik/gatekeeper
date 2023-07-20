#pragma maf add link argument "-L."
#pragma maf add link argument "-lsystemd"

namespace systemd {

void NotifyReady();
void PublishErrorsAsStatus();

// If the process is running under systemd with watchdog enabled, this function
// will periodically send watchdog pings.
//
// This function requires `epoll::Loop` to send the pings.
void StartWatchdog();

// Stop the watchdog pings started by `StartWatchdog()`.
void StopWatchdog();

} // namespace systemd