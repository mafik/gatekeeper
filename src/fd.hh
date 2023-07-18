#pragma once

#include "ip.hh"
#include "str.hh"

namespace maf {

// Wrapper around a file descriptor.
struct FD {
  int fd;

  FD();
  FD(int fd);
  FD(const FD &) = delete;
  FD(FD &&other);
  ~FD();

  operator int() const { return fd; }

  FD &operator=(const FD &) = delete;
  FD &operator=(FD &&other);

  void Close();

  void SetNonBlocking(maf::Status &);

  // TODO: move those into another header (fd_net.hh ?)
  void Bind(IP local_ip, U16 local_port, maf::Status &);
  void SendTo(IP remote_ip, U16 remote_port, StrView buffer, Str &error);
};

} // namespace maf