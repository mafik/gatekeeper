#include "fd.hh"

#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

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

void FD::Bind(IP ip, uint16_t port, std::string &error) {
  sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(port),
      .sin_addr = {.s_addr = ip.addr},
  };

  if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
    error = "bind: ";
    error += strerror(errno);
    return;
  }
}

void FD::SetNonBlocking(std::string &error) {
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0) {
    error = "fcntl(F_GETFL) failed: ";
    error += strerror(errno);
    return;
  }

  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    error = "fcntl(F_SETFL) failed: ";
    error += strerror(errno);
    return;
  }
}

void FD::SendTo(IP ip, uint16_t port, std::string_view buffer,
                std::string &error) {
  sockaddr_in dest_addr = {
      .sin_family = AF_INET,
      .sin_port = htons(port),
      .sin_addr = {.s_addr = ip.addr},
  };
  if (sendto(fd, buffer.data(), buffer.size(), 0, (struct sockaddr *)&dest_addr,
             sizeof(dest_addr)) < 0) {
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
