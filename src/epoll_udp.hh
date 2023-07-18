#pragma once

#include <string>
#include <string_view>

#include "epoll.hh"

struct UDPListener : maf::epoll::Listener {
  virtual void HandleRequest(std::string_view buf, maf::IP source_ip,
                             uint16_t source_port) = 0;

  void NotifyRead(maf::Status &) override;

private:
  uint8_t recvbuf[65536] = {0};
};
