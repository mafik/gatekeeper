#include "mac.hh"

#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "format.hh"

MAC MAC::FromInterface(std::string_view interface_name) {
  ifreq ifr = {};
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, interface_name.data(), IFNAMSIZ - 1);
  ioctl(sock, SIOCGIFHWADDR, &ifr);
  close(sock);
  return MAC(ifr.ifr_hwaddr.sa_data);
}

std::string MAC::to_string() const {
  return f("%02x:%02x:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2],
           bytes[3], bytes[4], bytes[5]);
}
