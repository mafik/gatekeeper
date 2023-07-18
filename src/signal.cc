#include "signal.hh"
#include "status.hh"

#include <csignal>
#include <sys/signalfd.h>

using namespace maf;

SignalHandler::SignalHandler(int signal, Status &status) : signal(signal) {
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, signal);

  if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
    AppendErrorMessage(status) += "sigprocmask(SIG_BLOCK)";
    return;
  }

  fd = signalfd(-1, &mask, 0);
  if (fd == -1) {
    AppendErrorMessage(status) += "signalfd";
    return;
  }
  epoll::Add(this, status);
  if (!OK(status)) {
    return;
  }
}

SignalHandler::~SignalHandler() {
  if (fd >= 0) {
    Status ignored;
    epoll::Del(this, ignored);
    close(fd);
  }
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, signal);
  sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

void SignalHandler::NotifyRead(Status &status) {
  signalfd_siginfo fdsi;
  ssize_t s = read(fd, &fdsi, sizeof(fdsi));
  if (s != sizeof(fdsi)) {
    AppendErrorMessage(status) += "signalfd: truncated read";
    return;
  }
  if (handler) {
    handler(status);
  }
}

const char *SignalHandler::Name() const { return "SignalHandler"; }
