#pragma once

#include "epoll.hh"
#include <functional>
#include <string>

struct Timer : epoll::Listener {
  std::string error;
  std::function<void()> handler;

  Timer();
  ~Timer();

  void Arm(double initial_s, double interval_s = 0);
  void Disarm();

  // Calls `handler` whenever the timer triggers. Part of the epoll::Listener
  // interface.
  void NotifyRead(std::string &error) override;

  const char *Name() const override;
};
