#include <algorithm>
#include <csignal>
#include <cstdlib>
#include <linux/if.h>
#include <linux/wireless.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include "config.hh"
#include "dhcp.hh"
#include "dns.hh"
#include "epoll.hh"
#include "etc.hh"
#include "firewall.hh"
#include "interface.hh"
#include "log.hh"
#include "netlink.hh"
#include "rtnetlink.hh"
#include "signal.hh"
#include "status.hh"
#include "systemd.hh"
#include "timer.hh"
#include "virtual_fs.hh"
#include "webui.hh"

using namespace gatekeeper;
using namespace maf;

std::optional<SignalHandler> sigabrt; // systemd watchdog
std::optional<SignalHandler> sigterm; // systemctl stop & systemd timeout
std::optional<SignalHandler> sigint;  // Ctrl+C

void StopSignal(const char *signal) {
  LOG << "Received " << signal << ". Stopping Gatekeeper.";
  webui::Stop();
  dns::Stop();
  dhcp::server.StopListening();
  systemd::StopWatchdog();
  // Signal handlers must be stopped so that epoll::Loop would terminate.
  sigabrt.reset();
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
  sigabrt.emplace(SIGABRT);
  sigabrt->handler = [](std::string &) { StopSignal("SIGABRT"); };
  if (!sigabrt->status.Ok()) {
    status = sigabrt->status;
    return;
  }
}

bool ConfirmInstall(const char *argv0) {
  LOG << "Gatekeeper will install itself to /opt/gatekeeper/. Press Ctrl+C "
         "within 10 seconds to abort.";
  bool confirmed = true;
  std::optional<SignalHandler> sigint;
  std::optional<Timer> timer;
  sigint.emplace(SIGINT);
  sigint->handler = [&](std::string &) {
    confirmed = false;
    LOG << "Aborting. You can run Gatekeeper without installing it by running "
           "it in a portable mode:\nPORTABLE=1 "
        << argv0;
    sigint.reset();
    timer.reset();
  };
  timer.emplace();
  timer->handler = [&]() {
    confirmed = true;
    sigint.reset();
    timer.reset();
  };
  timer->Arm(10);
  std::string err;
  epoll::Loop(err);
  return confirmed;
}

void Install(const char *argv0) {
  bool confirmed = ConfirmInstall(argv0);
  if (!confirmed) {
    return;
  }
  LOG << "- Creating /opt/gatekeeper/";
  int ret = mkdir("/opt/gatekeeper", 0755);
  if (ret == -1) {
    if (errno == EEXIST) {
      LOG << "  Already exists";
    } else {
      ERROR << "  Failed to create /opt/gatekeeper/: " << strerror(errno);
      return;
    }
  }
  LOG << "- Copying main binary";
  Status status;
  gatekeeper::CopyFile("/proc/self/exe", "/opt/gatekeeper/gatekeeper", status,
                       0755);
  if (!status.Ok()) {
    ERROR << "  Failed to copy main binary: " << status;
    return;
  }
  LOG << "- Copying systemd service file";
  gatekeeper::CopyFile("gatekeeper.service",
                       "/opt/gatekeeper/gatekeeper.service", status, 0644);
  if (!status.Ok()) {
    ERROR << "  Failed to copy systemd service file: " << status;
    return;
  }
  LOG << "- Installing systemd service";
  ret = system("systemctl enable --now /opt/gatekeeper/gatekeeper.service");
  if (ret == 0) {
    LOG << "\nInstallation finished successfully.";
  } else {
    LOG << "\nInstallation finished successfully but the service didn't start "
           "correctly. You might try running `systemctl edit gatekeeper` to "
           "provide it with some startup parameters & then `systemctl restart "
           "gatekeeper` to restart it.";
  }
  LOG << "\nRunning `" << argv0 << "` again will reinstall Gatekeeper.";
  LOG << R"(
From now on you can now use the `systemctl` command to manage the `gatekeeper` service.

  systemctl status gatekeeper    # to see the status of the service
  systemctl stop gatekeeper      # to stop the service
  systemctl start gatekeeper     # to start the service

Gatekeeper will now show the system journal for the installed service.
Press Ctrl+C to stop.
)";
  char const *args[] = {"journalctl", "-fu", "gatekeeper", nullptr};
  ret = execvp("journalctl", (char **)args);
  if (ret != 0) {
    ERROR << "  journalctl failed with exit code " << ret;
  }
}

Interface PickWANInterface(Status &status) {
  if (auto env_WAN = getenv("WAN")) {
    Interface if_WAN = {.name = env_WAN, .index = 0};
    ForEachInetrface([&](Interface &iface) {
      if (iface.name == env_WAN) {
        if_WAN = iface;
      }
    });
    return if_WAN;
  }
  Netlink netlink_route(NETLINK_ROUTE, status);
  if (!status.Ok()) {
    status() += "Couldn't establish netlink to NETLINK_ROUTE";
    return {};
  }
  Interface if_WAN = {};
  // Check the routing table for `default` route.
  rtnetlink::GetRoute(
      netlink_route,
      [&](rtnetlink::Route &r) {
        if (r.dst == IP(0, 0, 0, 0) && r.dst_mask == IP(0, 0, 0, 0) &&
            r.gateway.has_value() && r.oif.has_value()) {
          // Save the index of the interface that has the default route.
          if_WAN.index = r.oif.value();
        }
      },
      status);
  if (if_WAN.index) {
    // Find the interface with the saved index.
    ForEachInetrface([&](Interface &iface) {
      if (iface.index == if_WAN.index) {
        if_WAN = iface;
      }
    });
  }
  return if_WAN;
}

Interface PickLANInterface(Status &status) {
  if (auto env_LAN = getenv("LAN")) {
    Interface if_LAN = {.name = env_LAN, .index = 0};
    ForEachInetrface([&](Interface &iface) {
      if (iface.name == env_LAN) {
        if_LAN = iface;
      }
    });
    return if_LAN;
  }
  std::vector<Interface> candidates;
  ForEachInetrface([&](Interface &iface) {
    if (iface.IsLoopback()) { // skip loopback
      return;
    }
    if (iface.IsWireless()) { // skip wireless
      return;
    }
    Status ip_status;
    iface.IP(ip_status);
    if (ip_status.Ok()) { // skip interfaces with IPs
      return;
    }
    candidates.push_back(iface);
  });

  if (candidates.empty()) {
    status() += "Couldn't find any candidate interface";
    return {};
  }

  if (candidates.size() > 1) {
    // TODO: handle this by setting up a bridge
    std::string names;
    for (auto &iface : candidates) {
      names += " " + iface.name;
    }
    ERROR << "Found more than one candidate interface:" << names
          << ". Picking the first one: " << candidates[0].name;
  }

  return candidates[0];
}

Network PickUnusedSubnet(Status status) {
  // Consider networks with 16 bits for hosts
  IP netmask = IP::NetmaskFromPrefixLength(16);
  std::vector<IP> available;
  for (int i = 0; i < 256; ++i) {
    available.push_back(IP(10, i, 0, 0));
  }
  for (int i = 16; i < 32; ++i) {
    available.push_back(IP(172, i, 0, 0));
  }
  available.push_back(IP(192, 168, 0, 0));
  ForEachInetrface([&](Interface &iface) {
    Status status;
    IP if_ip = iface.IP(status);
    IP if_netmask = iface.Netmask(status);
    if (!status.Ok()) {
      return;
    }
    IP union_netmask = if_netmask & netmask;
    std::ranges::remove_if(available, [&](IP &available_ip) {
      return (if_ip & union_netmask) == (available_ip & union_netmask);
    });
  });
  if (available.empty()) {
    status() += "All private IP ranges are taken. Couldn't find an unused one.";
    return {};
  }
  return {.ip = available[0], .netmask = netmask};
}

void Deconfigure() {
  Status status;
  lan.Deconfigure(status);
  if (!status.Ok()) {
    ERROR << status;
  }
}

int main(int argc, char *argv[]) {
  std::string err;
  Status status;

  epoll::Init();

  bool portable = getenv("PORTABLE") != nullptr;
  bool under_systemd = getenv("NOTIFY_SOCKET") != nullptr;

  if (!portable && !under_systemd) {
    Install(argv[0]);
    return 0;
  }

  systemd::PublishErrorsAsStatus();

  HookSignals(status);
  if (!status.Ok()) {
    ERROR << status;
    return 1;
  }

  lan = PickLANInterface(status);
  if (!status.Ok()) {
    ERROR << status;
    return 1;
  }

  wan = PickWANInterface(status);
  if (!status.Ok()) {
    ERROR << status;
    return 1;
  }
  wan_ip = wan.IP(status);
  if (!status.Ok()) {
    ERROR << status;
    return 1;
  }
  LOG << "Found WAN interface " << wan.name << " with IP " << wan_ip;

  lan_network = lan.Network(status);
  bool externally_configured;
  if (status.Ok()) {
    LOG << "Using preconfigured " << lan.name << " with IP " << lan_network;
    externally_configured = true;
  } else {
    externally_configured = false;
    Status pick_status;
    lan_network = PickUnusedSubnet(pick_status);
    if (!pick_status.Ok()) {
      ERROR << status;
      ERROR << pick_status;
      return 1;
    }
    status.Reset();
    // Select the first IP in the subnet.
    lan_ip = lan_network.ip;
    ++lan_ip;
    LOG << "Configuring " << lan.name << " with IP " << lan_ip;
    lan.Configure(lan_ip, lan_network, status);
    if (!status.Ok()) {
      ERROR << status;
      return 1;
    }
    atexit(Deconfigure);
  }

  etc::ReadConfig();

  // Note: firewall can be started only after LAN & WAN are configured.
  firewall::Start(status);
  if (!status.Ok()) {
    status() += "Couldn't set up firewall";
    ERROR << status;
    return 1;
  }

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

  LOG << "Gatekeeper running at http://" << lan_ip << ":1337/";
  systemd::NotifyReady();
  systemd::StartWatchdog();

  epoll::Loop(err);
  if (!err.empty()) {
    ERROR << err;
    return 1;
  }
  LOG << "Gatekeeper stopped.";
  return 0;
}
