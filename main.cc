#include <string>

#include "config.hh"
#include "dhcp.hh"
#include "dns.hh"
#include "epoll.hh"
#include "etc.hh"
#include "log.hh"
#include "status.hh"
#include "systemd.hh"
#include "webui.hh"

int main(int argc, char *argv[]) {
  std::string err;
  Status status;

  systemd::PublishErrorsAsStatus();

  if (argc < 2) {
    ERROR << "Usage: " << argv[0] << " <interface>";
    return 1;
  }
  interface_name = argv[1];

  epoll::Init();

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
  return 0;
}
