#pragma once

namespace systemd {

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

} // namespace systemd