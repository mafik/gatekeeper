#include "interface.hh"
#include "fd.hh"
#include "status.hh"
#include "virtual_fs.hh"

#include <cerrno>
#include <cstring>
#include <linux/if.h>
#include <linux/sockios.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>
#include <unistd.h>

using namespace maf;

static void PrepareFD(FD &fd) {
  if (fd < 0) {
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  }
}

static void BringInterfaceUpDown(FD &fd, const Interface &iface, bool up,
                                 Status &status) {
  PrepareFD(fd);
  ifreq ifr = {};
  strncpy(ifr.ifr_name, iface.name.c_str(), IFNAMSIZ - 1);
  memset(&ifr.ifr_ifru, 0, sizeof(ifr.ifr_ifru));
  if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) { // get current flags
    AppendErrorMessage(status) += "ioctl(SIOCGIFFLAGS) failed";
    return;
  }
  if (up) {
    ifr.ifr_flags |= IFF_UP;
  } else {
    ifr.ifr_flags &= ~IFF_UP;
  }
  if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) { // set new flags
    AppendErrorMessage(status) += "ioctl(SIOCSIFFLAGS) failed";
    return;
  }
}

static void BringInterfaceUp(FD &fd, const Interface &iface, Status &status) {
  BringInterfaceUpDown(fd, iface, true, status);
  if (!OK(status)) {
    AppendErrorMessage(status) += "Couldn't bring up interface " + iface.name;
    return;
  }
}

static void BringInterfaceDown(FD &fd, const Interface &iface, Status &status) {
  BringInterfaceUpDown(fd, iface, false, status);
  if (!OK(status)) {
    AppendErrorMessage(status) += "Couldn't bring down interface " + iface.name;
    return;
  }
}

static void SetInterfaceIPv4(FD &fd, const Interface &iface, IP ip,
                             Status &status) {
  PrepareFD(fd);
  ifreq ifr = {};
  strncpy(ifr.ifr_name, iface.name.c_str(), IFNAMSIZ - 1);
  sockaddr_in *addr = (sockaddr_in *)&ifr.ifr_addr;
  // Assign IP
  addr->sin_family = AF_INET;
  addr->sin_addr.s_addr = ip.addr;
  if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
    AppendErrorMessage(status) +=
        "ioctl(SIOCSIFADDR, " + ToStr(ip) + ") failed";
    return;
  }
}

static Interface CreateBridge(FD &fd, const char *bridge_name, Status &status) {
  PrepareFD(fd);
  if (ioctl(fd, SIOCBRADDBR, bridge_name) < 0) {
    if (errno == EEXIST) {
      errno = 0;
    } else {
      AppendErrorMessage(status) +=
          "ioctl(SIOCBRADDBR, \"" + Str(bridge_name) + "\") failed";
      return {};
    }
  }
  Interface br = {.name = bridge_name, .index = 0};
  br.UpdateIndex(status);
  if (!OK(status)) {
    AppendErrorMessage(status) +=
        "Couldn't get index of newly created bridge " + Str(bridge_name);
    return {};
  }
  return br;
}

static void DeleteBridge(FD &fd, const char *bridge_name, Status &status) {
  PrepareFD(fd);
  if (ioctl(fd, SIOCBRDELBR, bridge_name) < 0) {
    AppendErrorMessage(status) +=
        "ioctl(SIOCBRDELBR, \"" + Str(bridge_name) + "\") failed";
    return;
  }
}

void DeleteBridge(const char *bridge_name, maf::Status &status) {
  FD fd;
  DeleteBridge(fd, bridge_name, status);
}

bool Interface::IsLoopback() {
  int fd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  ifreq ifr = {};
  strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
  if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
    close(fd);
    return false;
  }
  close(fd);
  return ifr.ifr_flags & IFF_LOOPBACK;
}

bool Interface::IsWireless() {
  int fd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  iwreq iw = {};
  strncpy(iw.ifr_name, name.c_str(), IFNAMSIZ - 1);
  if (ioctl(fd, SIOCGIWNAME, &iw) < 0) {
    close(fd);
    return false;
  }
  close(fd);
  return true;
}

IP Interface::IP(Status &status) { return IP::FromInterface(name, status); }

::IP Interface::Netmask(Status &status) {
  return IP::NetmaskFromInterface(name, status);
}

Network Interface::Network(Status &status) {
  auto ip = IP(status);
  auto netmask = Netmask(status);
  return {.ip = ip & netmask, .netmask = netmask};
}

void Interface::BringUp(Status &status) const {
  FD fd;
  BringInterfaceUp(fd, *this, status);
}

void Interface::BringDown(Status &status) const {
  FD fd;
  BringInterfaceDown(fd, *this, status);
}

void Interface::Configure(::IP ip, ::Network network, Status &status) {
  FD fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  // Assign IP
  SetInterfaceIPv4(fd, *this, ip, status);
  if (!OK(status)) {
    AppendErrorMessage(status) += "Couldn't set IP on interface " + name;
    return;
  }
  // Assign broadcast address
  ifreq ifr = {};
  strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
  sockaddr_in *addr = (sockaddr_in *)&ifr.ifr_addr;
  addr->sin_family = AF_INET;
  addr->sin_addr.s_addr = network.ip.addr | ~network.netmask.addr;
  if (ioctl(fd, SIOCSIFBRDADDR, &ifr) < 0) {
    status() += "Couldn't set broadcast address on interface " + name +
                " because ioctl(SIOCSIFBRDADDR) failed";
    return;
  }
  // Assign netmask
  addr->sin_addr.s_addr = network.netmask.addr;
  if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0) {
    status() += "Couldn't set netmask " + ToStr(network.netmask) +
                " on interface " + name +
                " because ioctl(SIOCSIFNETMASK) failed";
    return;
  }
  // Bring up the interface
  BringInterfaceUp(fd, *this, status);
  if (!OK(status)) {
    AppendErrorMessage(status) += "Couldn't configure interface " + name;
    return;
  }
  // Enable forwarding
  Path path = "/proc/sys/net/ipv4/conf/" + name + "/forwarding";
  fs::Write(fs::real, path, "1", status);
}

void Interface::Deconfigure(Status &status) {
  FD fd;
  SetInterfaceIPv4(fd, *this, ::IP(0, 0, 0, 0), status);
  if (!OK(status)) {
    AppendErrorMessage(status) += "Couldn't clear IP of interface " + name;
    return;
  }
  BringInterfaceDown(fd, *this, status);
}

void Interface::UpdateIndex(maf::Status &status) {
  FD fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  ifreq ifr = {};
  strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
  if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
    status() += "Couldn't update index of interface " + name +
                " because ioctl(SIOCGIFINDEX) failed";
    return;
  }
  index = ifr.ifr_ifindex;
}

void Interface::CheckName(StrView name, Status &status) {
  if (name.empty()) {
    AppendErrorMessage(status) += "Interface name cannot be empty";
    return;
  }
  if (name.size() >= IFNAMSIZ) {
    AppendErrorMessage(status) += "Interface name cannot be longer than " +
                                  std::to_string(IFNAMSIZ - 1) + " characters";
    return;
  }
  for (auto c : name) {
    if (c == '/') {
      AppendErrorMessage(status) += "Interface name cannot contain '/'";
      return;
    }
    if (isspace(c)) {
      AppendErrorMessage(status) += "Interface name cannot contain whitespace";
      return;
    }
  }
}

// Inlined declarations from <net/if.h> which conflicts with <linux/if.h>
struct if_nameindex {
  unsigned int if_index; /* 1, 2, ... */
  char *if_name;         /* null terminated name: "eth0", ... */
};
extern "C" struct if_nameindex *if_nameindex(void);
extern "C" void if_freenameindex(struct if_nameindex *ptr);

void ForEachInetrface(std::function<void(Interface &)> callback) {
  struct if_nameindex *if_begin = if_nameindex();
  for (auto it = if_begin; it->if_index != 0 && it->if_name != nullptr; ++it) {
    Interface iface = {.name = it->if_name, .index = it->if_index};
    callback(iface);
  }
  if_freenameindex(if_begin);
}

Interface BridgeInterfaces(const Vec<Interface> &interfaces,
                           const char *bridge_name, Status &status) {
  FD fd;
  PrepareFD(fd);
  Interface bridge = CreateBridge(fd, bridge_name, status);
  if (!OK(status)) {
    AppendErrorMessage(status) +=
        "Couldn't create bridge \"" + Str(bridge_name) + "\"";
    return {};
  }
  ifreq ifr = {};
  strncpy(ifr.ifr_name, bridge_name, IFNAMSIZ - 1);

  for (auto &iface : interfaces) {
    BringInterfaceUp(fd, iface, status);
    if (!OK(status)) {
      DeleteBridge(fd, bridge_name, status);
      return {};
    }
    ifr.ifr_ifindex = iface.index;
    if (ioctl(fd, SIOCBRADDIF, &ifr) < 0) {
      AppendErrorMessage(status) += "Couldn't add interface \"" + iface.name +
                                    "\" to bridge \"" + Str(bridge_name) + "\"";
      DeleteBridge(fd, bridge_name, status);
      return {};
    }
  }
  return bridge;
}