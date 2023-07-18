#pragma once

#include <functional>

#include "epoll.hh"
#include "status.hh"

struct SignalHandler : maf::epoll::Listener {
  std::function<void(maf::Status &)> handler;
  int signal;

  SignalHandler(int signal, maf::Status &);
  ~SignalHandler();

  // Calls `handler` whenever the signal is delivered. Part of the
  // epoll::Listener interface.
  void NotifyRead(maf::Status &) override;

  // Part of the epoll::Listener interface.
  const char *Name() const override;
};
