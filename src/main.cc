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
#include "interface.hh"
#include "log.hh"
#include "signal.hh"
#include "status.hh"
#include "systemd.hh"
#include "timer.hh"
#include "virtual_fs.hh"
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

Interface PickInterface(Status &status) {
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
  Interface iface = {.name = interface_name, .index = 0};
  iface.Deconfigure(status);
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

  Interface iface = PickInterface(status);
  if (!status.Ok()) {
    ERROR << status;
    return 1;
  }

  Network network = iface.Network(status);
  bool externally_configured;
  if (status.Ok()) {
    LOG << "Using preconfigured " << iface.name << " with IP " << network;
    externally_configured = true;
  } else {
    externally_configured = false;
    Status pick_status;
    network = PickUnusedSubnet(pick_status);
    if (!pick_status.Ok()) {
      ERROR << status;
      ERROR << pick_status;
      return 1;
    }
    status.Reset();
    // Select the first IP in the subnet.
    ++network.ip;
    LOG << "Configuring " << iface.name << " with IP " << network;
    iface.Configure(network, status);
    if (!status.Ok()) {
      ERROR << status;
      return 1;
    }
    atexit(Deconfigure);
  }

  // The rest of the code uses these globals.
  // TODO: Replace them with proper structs.
  interface_name = iface.name;
  server_ip = network.ip;
  netmask = network.netmask;

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

  LOG << "Gatekeeper running at http://" << server_ip << ":1337/";
  systemd::NotifyReady();

  epoll::Loop(err);
  if (!err.empty()) {
    ERROR << err;
    return 1;
  }
  LOG << "Gatekeeper stopped.";
  return 0;
}
