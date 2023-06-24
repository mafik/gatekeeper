#include "timer.hh"
#include "epoll.hh"
#include <bits/types/time_t.h>
#include <cassert>
#include <cstring>
#include <sys/timerfd.h>
#include <unistd.h>

Timer::Timer() {
  fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
  if (fd == -1) {
    error = "timerfd_create(): ";
    error += strerror(errno);
    return;
  }
  epoll::Add(this, error);
}

Timer::~Timer() {
  if (fd >= 0) {
    epoll::Del(this, error);
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
                      .tv_nsec = (long)((interval_s - (uint64_t)interval_s) *
                                        1000000000)},
      .it_value = {.tv_sec = (time_t)initial_s,
                   .tv_nsec =
                       (long)((initial_s - (uint64_t)initial_s) * 1000000000)}};
  if (timerfd_settime(fd, 0, &ts, nullptr) == -1) {
    error = "timerfd_settime(): ";
    error += strerror(errno);
    error += itimerspec_dump(&ts);
    close(fd);
    return;
  }
}

void Timer::Disarm() { Arm(0, 0); }

void Timer::NotifyRead(std::string &error) {
  uint64_t ticks;
  if (read(fd, &ticks, sizeof(ticks)) != sizeof(ticks)) {
    error = "Timer::NotifyRead read(): ";
    error += strerror(errno);
    return;
  }
  if (handler)
    handler();
}

const char *Timer::Name() const { return "Timer"; }
