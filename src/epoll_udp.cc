#include "epoll_udp.hh"
#include "status.hh"
#include <cstring>

namespace maf::epoll {

void UDPListener::NotifyRead(Status &status) {
  while (true) {
    sockaddr_in clientaddr;
    socklen_t clilen = sizeof(struct sockaddr);
    SSize len = recvfrom(fd, recvbuf, sizeof(recvbuf), 0,
                         (struct sockaddr *)&clientaddr, &clilen);
    if (len < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        errno = 0;
        break;
      } else {
        AppendErrorMessage(status) += "UDPListener recvfrom";
        return;
      }
    }
    IP source_ip(clientaddr.sin_addr.s_addr);
    U16 source_port = Big<U16>(clientaddr.sin_port).big_endian;
    HandleRequest(StrView((char *)recvbuf, len), source_ip, source_port);
  }
}

} // namespace maf::epoll