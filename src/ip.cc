#include "ip.hh"

#include "format.hh"

#include <cstring>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

IP IP::FromInterface(std::string_view interface_name, Status &status) {
  ifreq ifr = {};
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
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
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
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
  return IP(mask);
}

std::string IP::to_string() const {
  return f("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}
