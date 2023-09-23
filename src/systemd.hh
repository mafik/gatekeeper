#pragma once

#include "status.hh"
#include "str.hh"

namespace systemd {

// Returns true when the current process is running under systemd.
bool IsRunningUnderSystemd();

// Returns true when systemd is available on the system.
bool IsSystemdAvailable();

// Call this function after epoll::Init to setup systemd integration.
//
// This function does nothing when not running under systemd.
//
// When running under systemd:
// 1. Notifies systemd that the service is starting.
// 2. Configures logging (LOG, ERROR, etc.) to output structured information.
// 3. Starts a watchdog timer if systemd watchdog is enabled.
void Init();

// Call this function after the service is ready to start accepting connections.
//
// This function does nothing when not running under systemd.
void Ready();

// Call this function to stop systemd watchdog pings.
//
// This function does nothing when not running under systemd.
void Stop();

// Update /etc/systemd/system/<unit>.service.d/override.conf to set the given
// environment variable.
void OverrideEnvironment(maf::StrView unit, maf::StrView env,
                         maf::StrView value, maf::Status &status);

} // namespace systemd