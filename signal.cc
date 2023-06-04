#include "signal.hh"

#include <csignal>
#include <sys/signalfd.h>

SignalHandler::SignalHandler(int signal) {
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, signal);

  if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
    status() += "sigprocmask(SIG_BLOCK)";
    return;
  }

  fd = signalfd(-1, &mask, 0);
  if (fd == -1) {
    status() += "signalfd";
    return;
  }
  std::string error;
  epoll::Add(this, error);
  if (!error.empty()) {
    status() += error;
    return;
  }
}

SignalHandler::~SignalHandler() {
  if (fd >= 0) {
    std::string error;
    epoll::Del(this, error);
    close(fd);
  }
}

void SignalHandler::NotifyRead(std::string &error) {
  signalfd_siginfo fdsi;
  ssize_t s = read(fd, &fdsi, sizeof(fdsi));
  if (s != sizeof(fdsi)) {
    error = "signalfd: truncated read";
    return;
  }
  if (handler) {
    handler(error);
  }
}

const char *SignalHandler::Name() const { return "SignalHandler"; }
