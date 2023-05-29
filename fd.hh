#pragma once

// Wrapper around a file descriptor.

#include <string>

#include "ip.hh"

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

  void Bind(IP ip, uint16_t port, std::string &error);
  void SetNonBlocking(std::string &error);
  void SendTo(IP ip, uint16_t port, std::string_view buffer,
              std::string &error);

  void Close();
};
