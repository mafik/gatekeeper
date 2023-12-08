#include "ip.hh"

#include "format.hh"

#include <cstring>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace maf {

const IP IP::kZero;

IP IP::FromInterface(std::string_view interface_name, Status &status) {
  ifreq ifr = {};
  int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  strncpy(ifr.ifr_name, interface_name.data(), IFNAMSIZ - 1);
  if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
    status() = "ioctl(SIOCGIFADDR) failed";
    close(sock);
    return IP();
  }
  close(sock);
  return IP(((sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
}

IP IP::NetmaskFromInterface(std::string_view interface_name, Status &status) {
  ifreq ifr = {};
  int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, interface_name.data(), IFNAMSIZ - 1);
  if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0) {
    status() = "ioctl(SIOCGIFNETMASK) failed";
    close(sock);
    return IP();
  }
  close(sock);
  return IP(((sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
}

IP IP::NetmaskFromPrefixLength(int prefix_length) {
  uint32_t mask = 0;
  for (int i = 0; i < prefix_length; i++) {
    mask |= 1 << (31 - i);
  }
  return IP(htonl(mask));
}

Str ToStr(IP ip) {
  return f("%d.%d.%d.%d", ip.bytes[0], ip.bytes[1], ip.bytes[2], ip.bytes[3]);
}

Str ToStr(const Network &n) {
  return ToStr(n.ip) + "/" + ToStr(std::countr_one(n.netmask.addr));
}

} // namespace maf