#pragma once

#include <functional>

#include "epoll.hh"
#include "status.hh"

struct SignalHandler : epoll::Listener {
  Status status;
  std::function<void(std::string &error)> handler;

  SignalHandler(int signal);
  ~SignalHandler();

  // Calls `handler` whenever the signal is delivered. Part of the
  // epoll::Listener interface.
  void NotifyRead(std::string &error) override;

  // Part of the epoll::Listener interface.
  const char *Name() const override;
};
