// Gatekeeper is a combined DHCP server & DNS proxy for home networks. It's
// designed to run on the gateway router of a home network. It's web interface
// allows the user to easily inspect the state of the network: see what devices
// are connected and snoop on DNS requests by IoT devices.

#include <string>

#include "config.hh"
#include "dhcp.hh"
#include "dns.hh"
#include "epoll.hh"
#include "etc.hh"
#include "log.hh"
#include "webui.hh"

int main(int argc, char *argv[]) {
  std::string err;

  if (argc < 2) {
    ERROR << "Usage: " << argv[0] << " <interface>";
    return 1;
  }
  interface_name = argv[1];

  epoll::Init();

  server_ip = IP::FromInterface(interface_name, err);
  if (!err.empty()) {
    ERROR << "Couldn't obtain IP for interface " << interface_name << ": "
          << err;
    return 1;
  }
  netmask = IP::NetmaskFromInterface(interface_name, err);
  if (!err.empty()) {
    ERROR << "Couldn't obtain netmask for interface " << interface_name << ": "
          << err;
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
  epoll::Loop(err);
  if (!err.empty()) {
    ERROR << err;
    return 1;
  }
  return 0;
}
