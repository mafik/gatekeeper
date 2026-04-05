#include "arp.hh"

#include <net/if_arp.h>
#include <sys/ioctl.h>

#include "status.hh"

namespace automat::arp {

struct IOCtlRequest {
  struct sockaddr_in protocol_address;
  struct sockaddr hardware_address;
  int flags;
  struct sockaddr netmask; /* Only for proxy arps.  */
  char device[16];
};

static_assert(sizeof(IOCtlRequest) == sizeof(arpreq),
              "IOCtlRequest doesn't match `struct arpreq` from <net/if_arp.h>");

void Set(const std::string& interface, IP ip, MAC mac, int af_inet_fd, Status& status) {
  IOCtlRequest r{
      .protocol_address = {.sin_family = AF_INET, .sin_addr = {.s_addr = ip.addr}},
      .hardware_address = {.sa_family = AF_UNSPEC,
                           .sa_data = {(char)mac[0], (char)mac[1], (char)mac[2], (char)mac[3],
                                       (char)mac[4], (char)mac[5]}},
      .flags = ATF_COM | ATF_PERM,  // PERM helps with reponsiveness power-saving IoT devices that
                                    // don't respond to unicast ARP requests, and have to be woken
                                    // up by a broadcast ARP (delivered during DTIM).
  };
  strncpy(r.device, interface.c_str(), sizeof(r.device));
  if (ioctl(af_inet_fd, SIOCSARP, &r) < 0) {
    AppendErrorMessage(status) += "ioctl(SIOCSARP) failed";
  }
}

}  // namespace automat::arp