#pragma once

#include <chrono>
#include <map>
#include <optional>
#include <string>

#include "epoll_udp.hh"

namespace dhcp {

struct Server : UDPListener {

  struct Entry {
    std::string client_id;
    std::string hostname;
    std::optional<std::chrono::steady_clock::time_point> expiration;
    bool stable = false;
    std::optional<std::chrono::steady_clock::time_point> last_request;
  };

  std::map<IP, Entry> entries;

  void Init();

  // Start listening.
  //
  // To actually accept new connections, make sure to Poll the `epoll`
  // instance after listening.
  void Listen(std::string &error);

  // Stop listening.
  void StopListening();

  void HandleRequest(std::string_view buf, IP source_ip,
                     uint16_t port) override;

  const char *Name() const override;
};

extern Server server;

} // namespace dhcp