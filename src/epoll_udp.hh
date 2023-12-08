#pragma once

#include <string>
#include <string_view>

#include "epoll.hh"
#include "int.hh"
#include "str.hh"

namespace maf::epoll {

struct UDPListener : Listener {
  virtual void HandleRequest(StrView buf, IP source_ip, U16 source_port) = 0;

  void NotifyRead(Status &) override;

private:
  U8 recvbuf[65536] = {0};
};

} // namespace maf::epoll