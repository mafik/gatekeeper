#pragma once

#include <functional>

#include "epoll.hh"
#include "status.hh"

struct SignalHandler : automat::epoll::Listener {
  std::function<void(automat::Status &)> handler;
  int signal;

  SignalHandler(int signal, automat::Status &);
  ~SignalHandler();

  // Calls `handler` whenever the signal is delivered. Part of the
  // epoll::Listener interface.
  void NotifyRead(automat::Status &) override;

  // Part of the epoll::Listener interface.
  const char *Name() const override;
};
