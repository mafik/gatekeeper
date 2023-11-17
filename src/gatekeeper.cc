#include "gatekeeper.hh"

#include <algorithm>
#include <csignal>
#include <cstdlib>
#include <ctime>

#include "../build/generated/version.hh"
#include "atexit.hh"
#include "config.hh"
#include "dhcp.hh"
#include "dns_client.hh"
#include "dns_server.hh"
#include "epoll.hh"
#include "etc.hh"
#include "firewall.hh"
#include "format.hh"
#include "gatekeeper.hh"
#include "interface.hh"
#include "log.hh"
#include "netlink.hh"
#include "passgen.hh"
#include "proc.hh"
#include "random.hh"
#include "rtnetlink.hh"
#include "sig.hh" // IWYU pragma: keep
#include "signal.hh"
#include "sock_diag.hh"
#include "split.hh"
#include "status.hh"
#include "systemd.hh"
#include "unique_ptr.hh"
#include "update.hh"
#include "webui.hh"
#include "wifi.hh"
#include "xdg.hh"

#pragma maf main

using namespace std;
using namespace gatekeeper;
using namespace maf;

Optional<SignalHandler> sigabrt; // systemd watchdog
Optional<SignalHandler> sigterm; // systemctl stop & systemd timeout
Optional<SignalHandler> sigint;  // Ctrl+C

Vec<UniquePtr<wifi::AccessPoint>> wifi_access_points;

void StopSignal(const char *signal) {
  LOG << "Received " << signal << ". Stopping Gatekeeper.";
  webui::Stop();
  dns::StopServer();
  dns::StopClient();
  dhcp::server.StopListening();
  systemd::Stop();
  update::Stop();
  firewall::Stop();
  wifi_access_points.clear();
  // Signal handlers must be stopped so that epoll::Loop would terminate.
  UnhookSignals();
}

void gatekeeper::HookSignals(Status &status) {
  sigterm.emplace(SIGTERM, status);
  sigterm->handler = [](Status &) { StopSignal("SIGTERM"); };
  if (!OK(status)) {
    return;
  }
  sigint.emplace(SIGINT, status);
  sigint->handler = [](Status &) { StopSignal("SIGINT"); };
  if (!OK(status)) {
    return;
  }
  sigabrt.emplace(SIGABRT, status);
  sigabrt->handler = [](Status &) { StopSignal("SIGABRT"); };
  if (!OK(status)) {
    return;
  }
}

void gatekeeper::UnhookSignals() {
  sigabrt.reset();
  sigterm.reset();
  sigint.reset();
}

const char *gatekeeper::kKnownEnvironmentVariables[] = {
    "LAN", "WAN", "NO_AUTO_UPDATE", "WIFI_PASSWORD", "WIFI_NAME", nullptr};

// Get Environment Variable `name` or call `default_fn` and return its result.
//
// If `persist_default` is true, then save the result of `default_fn` so that
// subsequent calls will return the same value.
static Str GetEnvDefault(const char *name, Fn<Str()> default_fn,
                         bool persist_default = false) {
  if (auto env = getenv(name)) {
    return env;
  }
  auto default_value = default_fn();
  if (persist_default) {
    Status status;
    if (setenv(name, default_value.c_str(), 1) == -1) {
      AppendErrorMessage(status) += f("Couldn't save %s in env", name);
      FATAL << status;
    }
    if (systemd::IsRunningUnderSystemd()) {
      systemd::OverrideEnvironment("gatekeeper", name, default_value, status);
      if (!OK(status)) {
        AppendErrorMessage(status) +=
            f("Couldn't save %s in systemd service environment", name);
        FATAL << status;
      }
    }
  }
  return default_value;
}

StrView GetWifiPassword() {
  static Str wifi_password =
      GetEnvDefault("WIFI_PASSWORD", RandomPassword52bit, true);
  return wifi_password;
}

StrView GetWifiName() {
  static Str wifi_name =
      GetEnvDefault("WIFI_NAME", []() { return etc::hostname; });
  return wifi_name;
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
  Vec<Interface> candidates;
  if (auto LAN_env = getenv("LAN")) {
    // The user specified LAN interfaces through an environment variable.
    // Let's put them in the `candidates` list.
    Vec<StrView> LAN_vec = SplitOnChars(LAN_env, " ");
    for (auto &ifname : LAN_vec) {
      Interface::CheckName(ifname, status);
      if (!OK(status)) {
        AppendErrorMessage(status) += "An interface specified in the 'LAN' "
                                      "environment variable has invalid name";
        return {};
      }
    }
    ForEachInetrface([&](Interface &iface) {
      if (LAN_vec.Contains(iface.name)) {
        candidates.push_back(iface);
        LAN_vec.Erase(iface.name);
      }
    });
    if (!LAN_vec.empty()) {
      auto &msg = AppendErrorMessage(status);

      msg += "The 'LAN' environment variable contains ";
      if (LAN_vec.size() == 1) {
        msg += "an interface";
      } else {
        msg += "interfaces";
      }
      msg += " that couldn't be found in the system:";
      bool first = true;
      for (auto &ifname : LAN_vec) {
        if (not first) {
          msg += ',';
        } else {
          first = false;
        }
        msg += " \"";
        msg += ifname;
        msg += '\"';
      }
      msg += '.';
      return {};
    }
  } else {
    // Try to guess which interfaces could be part of LAN.
    ForEachInetrface([&](Interface &iface) {
      if (iface.IsLoopback()) { // skip loopback
        return;
      }
      // TODO: try DHCP INFORM probe
      Status ip_status;
      iface.IP(ip_status);
      if (OK(ip_status)) { // skip interfaces with IPs
        return;
      }
      candidates.push_back(iface);
    });
  }

  systemd::MaskGuard wpa_supplicant_mask_guard("wpa_supplicant");
  for (int i = 0; i < candidates.size(); ++i) {
    auto &iface = candidates[i];
    if (iface.IsWireless()) {
      LOG << "Starting Wi-Fi access point on interface \"" << iface.name
          << "\".";
      StrView password = GetWifiPassword();
      Status wifi_status;
      wifi_access_points.emplace_back(
          new wifi::AccessPoint(iface, wifi::Band::kPrefer5GHz, etc::hostname,
                                "password"sv, wifi_status));
      if (!OK(wifi_status)) {
        ERROR << "Couldn't configure Wi-Fi on interface " << iface.name << ". "
              << wifi_status;
        wifi_access_points.pop_back();
        candidates.erase(candidates.begin() + i);
        --i;
      }
    }
  }

  if (!wifi_access_points.empty()) {
    LOG << "Wi-Fi password: " << GetWifiPassword();
  }

  if (candidates.empty()) {
    status() += "Couldn't find any candidate interface";
    return {};
  } else if (candidates.size() > 1) {
    Str names;
    for (auto &iface : candidates) {
      names += " " + iface.name;
    }
    LOG << "LAN contains multiple interfaces:" << names << ".";
    Interface bridge = BridgeInterfaces(candidates, "lan", status);
    if (!OK(status)) {
      return {};
    }
    AtExit([]() {
      for (auto &slave : lan_bridge_slaves) {
        Status status;
        slave.Deconfigure(status);
        if (!status.Ok()) {
          ERROR << status;
        }
      }
      lan_bridge_slaves.clear();
      Status status;
      DeleteBridge("lan", status);
      if (!status.Ok()) {
        ERROR << status;
      }
    });
    lan_bridge_slaves = candidates;
    LOG << "Created LAN bridge interface \"" << bridge.name << "\".";
    return bridge;
  } else {
    return candidates.front();
  }
}

Network PickUnusedSubnet(Status &status) {
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
    status.Reset();
  }
}

void KillConflictingProcesses(Status &status) {
  std::unordered_set<U32> inodes, pids;
  ScanUdpSockets(
      [&](InternetSocketDescription &desc) {
        // Include DHCP (67) & DNS (53).
        if (desc.local_port == 53 || desc.local_port == 67) {
          if (desc.local_ip.bytes[0] == 127) {
            return; // Ignore apps that listen only on localhost (like
                    // systemd-resolved).
          }
          if (desc.local_ip != IP::kZero && desc.local_ip != wan_ip &&
              desc.local_ip != lan_ip) {
            return; // Ignore apps that listen on other IPs.
          }
          if (desc.interface != 0 && desc.interface != wan.index &&
              desc.interface != lan.index) {
            return; // Ignore apps that listen on other interfaces.
          }
          inodes.insert(desc.inode);
        }
      },
      status);
  RETURN_ON_ERROR(status);
  ScanTcpSockets(
      [&](InternetSocketDescription &desc) {
        if (desc.local_port == 1337) {
          inodes.insert(desc.inode);
        }
      },
      status);
  RETURN_ON_ERROR(status);
  for (U32 pid : ScanProcesses(status)) {
    for (auto opened_inode : ScanOpenedSockets(pid, status)) {
      RETURN_ON_ERROR(status);
      if (inodes.contains(opened_inode)) {
        pids.insert(pid);
        break;
      }
    }
  }
  RETURN_ON_ERROR(status);
  U32 my_pid = getpid();
  if (pids.contains(my_pid)) {
    // Current Gatekeeper process is already listening on the vital ports.
    //
    // This might have happened as a result of a bug present in v1.6.0 which
    // didn't use SO_CLOEXEC.
    //
    // We deliberately allow the current process to proceed & crash while
    // binding DNS & DHCP ports because it leads to cleaner error messages &
    // systemd will restart us anyway.
    pids.erase(my_pid);
  }
  for (U32 pid : pids) {
    Status status_ignored;
    LOG << "Killing conflicting process \""
        << GetProcessName(pid, status_ignored) << "\" (PID=" << pid << ")";
    kill(pid, SIGKILL);
  }
}

int main(int argc, char *argv[]) {
  Status status;

  epoll::Init();

  systemd::Init();

  LOG << "Gatekeeper " << kVersionNote.desc << " starting up.";

  HookSignals(status);
  if (!status.Ok()) {
    ERROR << status;
    return 1;
  }

  bool no_auto_update = getenv("NO_AUTO_UPDATE") != nullptr;
  bool auto_update = !no_auto_update;

  if (auto_update) {
    update::config.first_check_delay_s =
        15 * 60 + (random<U32>() % (24 * 60 * 60));
    update::config.check_interval_s = 7 * 24 * 60 * 60;
    update::config.url = "https://github.com/mafik/gatekeeper/releases/latest/"
                         "download/gatekeeper.x86_64";
    if (!OK(status)) {
      ERROR << status;
      return 1;
    }
    update::Start();
    if (!OK(update::status)) {
      ERROR << update::status;
      return 1;
    }
  }

  etc::ReadConfig();

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
    AppendErrorMessage(status) += "WAN interface doesn't have an IP address";
    AppendErrorAdvice(
        status,
        "Gatekeeper relies on the operating system to configure the external "
        "internet connection. Try going into internet settings and enable DHCP "
        "(sometimes called \"automatic\" configuration).");
    ERROR << status;
    return 1;
  }
  LOG << "Found WAN interface " << wan.name << " with IP " << wan_ip;

  lan_network = lan.Network(status);
  if (OK(status)) {
    lan_ip = lan.IP(status);
  }
  if (status.Ok()) {
    LOG << "Using preconfigured " << lan.name << " with IP " << lan_network;
  } else {
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
    AtExit(Deconfigure);
  }

  KillConflictingProcesses(status);
  if (!OK(status)) {
    status() += "Couldn't kill conflicting processes";
    ERROR << status;
    return 1;
  }

  // Note: firewall can be started only after LAN & WAN are configured.
  firewall::Start(status);
  if (!status.Ok()) {
    status() += "Couldn't set up firewall";
    ERROR << status;
    return 1;
  }

  dhcp::server.Init();
  dhcp::server.Listen(status);
  if (!OK(status)) {
    ERROR << "Failed to start DHCP server: " << status;
    return 1;
  }

  dns::StartClient(status);
  if (!OK(status)) {
    ERROR << status;
    return 1;
  }

  dns::StartServer(status);
  if (!OK(status)) {
    ERROR << status;
    return 1;
  }

  webui::Start(status);
  if (!OK(status)) {
    ERROR << status;
    return 1;
  }

  LOG << "Gatekeeper running at http://" << lan_ip << ":1337/";
  systemd::Ready();
  if (not systemd::IsRunningUnderSystemd()) {
    Str url = f("http://%s:1337/", lan_ip.to_string().c_str());
    Status status_ignored;
    xdg::Open(url, status_ignored);
  }

  epoll::Loop(status);
  if (!OK(status)) {
    ERROR << status;
    return 1;
  }
  LOG << "Gatekeeper stopped.";
  return 0;
}
