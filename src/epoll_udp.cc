#include "epoll_udp.hh"
#include "status.hh"
#include <cstring>

using namespace maf;

void UDPListener::NotifyRead(Status &status) {
  while (true) {
    sockaddr_in clientaddr;
    socklen_t clilen = sizeof(struct sockaddr);
    ssize_t len = recvfrom(fd, recvbuf, sizeof(recvbuf), 0,
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
    uint16_t source_port = ntohs(clientaddr.sin_port);
    HandleRequest(std::string_view((char *)recvbuf, len), source_ip,
                  source_port);
  }
}
