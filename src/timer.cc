#include "timer.hh"
#include "epoll.hh"
#include "status.hh"

#include <cassert>
#include <cstring>
#include <sys/timerfd.h>
#include <unistd.h>

using namespace maf;

Timer::Timer() {
  fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
  if (fd == -1) {
    AppendErrorMessage(status) += "timerfd_create()";
    return;
  }
  epoll::Add(this, status);
}

Timer::~Timer() {
  if (fd >= 0) {
    epoll::Del(this, status);
    close(fd);
  }
}

static char *itimerspec_dump(struct itimerspec *ts) {
  static char buf[1024];

  snprintf(buf, sizeof(buf),
           "itimer: [ interval=%lu s %lu ns, next expire=%lu s %lu ns ]",
           ts->it_interval.tv_sec, ts->it_interval.tv_nsec, ts->it_value.tv_sec,
           ts->it_value.tv_nsec);

  return (buf);
}

void Timer::Arm(double initial_s, double interval_s) {
  itimerspec ts = {
      .it_interval = {.tv_sec = (time_t)interval_s,
                      .tv_nsec =
                          (long)((interval_s - (U64)interval_s) * 1000000000)},
      .it_value = {.tv_sec = (time_t)initial_s,
                   .tv_nsec =
                       (long)((initial_s - (U64)initial_s) * 1000000000)}};
  if (timerfd_settime(fd, 0, &ts, nullptr) == -1) {
    Str &err = AppendErrorMessage(status);
    err += "timerfd_settime(): ";
    err += itimerspec_dump(&ts);
    close(fd);
    return;
  }
}

void Timer::Disarm() { Arm(0, 0); }

void Timer::NotifyRead(Status &epoll_status) {
  U64 ticks;
  if (read(fd, &ticks, sizeof(ticks)) != sizeof(ticks)) {
    AppendErrorMessage(epoll_status) += "read() in Timer::NotifyRead";
    return;
  }
  if (handler)
    handler();
}

const char *Timer::Name() const { return "Timer"; }
