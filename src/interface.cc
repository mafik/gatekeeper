#include "interface.hh"
#include "virtual_fs.hh"

#include <cstring>
#include <linux/if.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>
#include <unistd.h>

using namespace maf;

bool Interface::IsLoopback() {
  int fd = socket(PF_INET, SOCK_DGRAM, 0);
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
  int fd = socket(PF_INET, SOCK_DGRAM, 0);
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

void Interface::Configure(::IP ip, ::Network network, Status &status) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  ifreq ifr = {};
  strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
  sockaddr_in *addr = (sockaddr_in *)&ifr.ifr_addr;
  // Assign IP
  addr->sin_family = AF_INET;
  addr->sin_addr.s_addr = ip.addr;
  if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
    status() += "Couldn't set IP on interface " + name +
                " because ioctl(SIOCSIFADDR) failed";
    close(fd);
    return;
  }
  // Assign broadcast address
  addr->sin_addr.s_addr = network.ip.addr | ~network.netmask.addr;
  if (ioctl(fd, SIOCSIFBRDADDR, &ifr) < 0) {
    status() += "Couldn't set broadcast address on interface " + name +
                " because ioctl(SIOCSIFBRDADDR) failed";
    close(fd);
    return;
  }
  // Assign netmask
  addr->sin_addr.s_addr = network.netmask.addr;
  if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0) {
    status() += "Couldn't set netmask " + network.netmask.to_string() +
                " on interface " + name +
                " because ioctl(SIOCSIFNETMASK) failed";
    close(fd);
    return;
  }
  // Bring up the interface
  memset(&ifr.ifr_ifru, 0, sizeof(ifr.ifr_ifru));
  if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) { // get current flags
    status() += "Couldn't bring up interface " + name +
                " because ioctl(SIOCGIFFLAGS) failed";
    close(fd);
    return;
  }
  ifr.ifr_flags |= IFF_UP;
  if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) { // set new flags
    status() += "Couldn't bring up interface " + name +
                " because ioctl(SIOCSIFFLAGS) failed";
    close(fd);
    return;
  }
  // Enable forwarding
  std::string path = "/proc/sys/net/ipv4/conf/" + name + "/forwarding";
  gatekeeper::WriteFile(path.c_str(), "1", status);
  close(fd);
}

void Interface::Deconfigure(Status &status) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  ifreq ifr = {};
  strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
  sockaddr_in *addr = (sockaddr_in *)&ifr.ifr_addr;
  // Assign IP
  addr->sin_family = AF_INET;
  addr->sin_addr.s_addr = 0;
  if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
    status() += "Couldn't clear IP of interface " + name +
                " because ioctl(SIOCSIFADDR) failed";
    close(fd);
    return;
  }
  close(fd);
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
