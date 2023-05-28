#include "ip.hh"

#include "format.hh"

#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstring>

IP IP::FromInterface(std::string_view interface_name, std::string& error) {
  ifreq ifr = {};
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, interface_name.data(), IFNAMSIZ - 1);
  if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
    error = f("ioctl(SIOCGIFADDR) failed: %s", strerror(errno));
    close(sock);
    return IP();
  }
  close(sock);
  return IP(((sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr);
}

IP IP::NetmaskFromInterface(std::string_view interface_name, std::string& error) {
  ifreq ifr = {};
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, interface_name.data(), IFNAMSIZ - 1);
  if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0) {
    error = f("ioctl(SIOCGIFNETMASK) failed: %s", strerror(errno));
    close(sock);
    return IP();
  }
  close(sock);
  return IP(((sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr);
}

std::string IP::to_string() const {
  return f("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}
