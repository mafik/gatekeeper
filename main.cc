#include <csignal>
#include <string>

#include "config.hh"
#include "dhcp.hh"
#include "dns.hh"
#include "epoll.hh"
#include "etc.hh"
#include "log.hh"
#include "signal.hh"
#include "status.hh"
#include "systemd.hh"
#include "webui.hh"

std::optional<SignalHandler> sigterm;
std::optional<SignalHandler> sigint;

void StopSignal(const char *signal) {
  LOG << "Received " << signal << ". Stopping Gatekeeper.";
  webui::Stop();
  dns::Stop();
  dhcp::server.StopListening();
  // Signal handlers must be stopped so that epoll::Loop would terminate.
  sigterm.reset();
  sigint.reset();
}

void HookSignals(Status &status) {
  sigterm.emplace(SIGTERM);
  sigterm->handler = [](std::string &) { StopSignal("SIGTERM"); };
  if (!sigterm->status.Ok()) {
    status = sigterm->status;
    return;
  }
  sigint.emplace(SIGINT);
  sigint->handler = [](std::string &) { StopSignal("SIGINT"); };
  if (!sigint->status.Ok()) {
    status = sigint->status;
    return;
  }
}

int main(int argc, char *argv[]) {
  std::string err;
  Status status;

  systemd::PublishErrorsAsStatus();

  epoll::Init();

  HookSignals(status);
  if (!status.Ok()) {
    ERROR << status;
    return 1;
  }

  if (argc < 2) {
    ERROR << "Usage: " << argv[0] << " <interface>";
    return 1;
  }
  interface_name = argv[1];

  server_ip = IP::FromInterface(interface_name, status);
  if (!status.Ok()) {
    status() += "Couldn't obtain IP for interface " + interface_name;
    ERROR << status;
    return 1;
  }
  netmask = IP::NetmaskFromInterface(interface_name, status);
  if (!status.Ok()) {
    status() += "Couldn't obtain netmask for interface " + interface_name;
    ERROR << status;
    return 1;
  }

  etc::ReadConfig();

  dhcp::server.Init();
  dhcp::server.Listen(err);
  if (!err.empty()) {
    ERROR << "Failed to start DHCP server: " << err;
    return 1;
  }

  dns::Start(err);
  if (!err.empty()) {
    ERROR << err;
    return 1;
  }

  webui::Start(err);
  if (!err.empty()) {
    ERROR << err;
    return 1;
  }

  LOG << "Gatekeeper started.";
  systemd::NotifyReady();

  epoll::Loop(err);
  if (!err.empty()) {
    ERROR << err;
    return 1;
  }
  LOG << "Gatekeeper stopped.";
  return 0;
}
