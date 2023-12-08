#include "mac.hh"

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "format.hh"

using namespace maf;

static_assert(sizeof(MAC) == 6, "MAC must be 6 bytes");

MAC MAC::FromInterface(std::string_view interface_name) {
  ifreq ifr = {};
  int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, interface_name.data(), IFNAMSIZ - 1);
  ioctl(sock, SIOCGIFHWADDR, &ifr);
  close(sock);
  return MAC(ifr.ifr_hwaddr.sa_data);
}

std::string MAC::ToStr() const {
  return f("%02x:%02x:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2],
           bytes[3], bytes[4], bytes[5]);
}
