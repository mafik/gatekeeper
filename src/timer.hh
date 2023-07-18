#pragma once

#include "epoll.hh"
#include <functional>
#include <string>

struct Timer : maf::epoll::Listener {
  maf::Status status;
  std::function<void()> handler;

  Timer();
  ~Timer();

  void Arm(double initial_s, double interval_s = 0);
  void Disarm();

  // Calls `handler` whenever the timer triggers. Part of the epoll::Listener
  // interface.
  void NotifyRead(maf::Status &) override;

  const char *Name() const override;
};
