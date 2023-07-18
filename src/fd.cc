#include "fd.hh"
#include "status.hh"

#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace maf {

FD::FD() : fd(-1) {}
FD::FD(int fd) : fd(fd) {}
FD::FD(FD &&other) : fd(other.fd) { other.fd = -1; }
FD::~FD() { Close(); }

FD &FD::operator=(FD &&other) {
  Close();
  fd = other.fd;
  other.fd = -1;
  return *this;
}

void FD::SetNonBlocking(Status &status) {
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0) {
    AppendErrorMessage(status) += "fcntl(F_GETFL) failed";
    return;
  }

  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    AppendErrorMessage(status) += "fcntl(F_SETFL) failed";
    return;
  }
}

void FD::Bind(IP local_ip, U16 local_port, Status &status) {
  sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(local_port),
      .sin_addr = {.s_addr = local_ip.addr},
  };

  if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
    AppendErrorMessage(status) += "bind";
    return;
  }
}

void FD::SendTo(IP remote_ip, U16 remote_port, StrView buffer, Str &error) {
  sockaddr_in remote_addr = {
      .sin_family = AF_INET,
      .sin_port = htons(remote_port),
      .sin_addr = {.s_addr = remote_ip.addr},
  };
  if (sendto(fd, buffer.data(), buffer.size(), 0,
             (struct sockaddr *)&remote_addr, sizeof(remote_addr)) < 0) {
    error = "sendto: ";
    error += strerror(errno);
  }
}

void FD::Close() {
  if (fd >= 0) {
    close(fd);
    fd = -1;
  }
}

} // namespace maf