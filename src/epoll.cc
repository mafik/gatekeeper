#include "epoll.hh"

#include <cstring>
#include <fcntl.h>
#include <sys/epoll.h>

// #define DEBUG_EPOLL

#ifdef DEBUG_EPOLL
#include "log.hh"
#endif

namespace maf::epoll {

thread_local int fd = 0;
thread_local int listener_count = 0;

static constexpr int kMaxEpollEvents = 10;
static epoll_event events[kMaxEpollEvents];
static int events_count = 0;

void Init() { fd = epoll_create1(EPOLL_CLOEXEC); }

static epoll_event MakeEpollEvent(Listener *listener) {
  epoll_event ev = {.events = 0, .data = {.ptr = listener}};
  if (listener->notify_read) {
    ev.events |= EPOLLIN;
  }
  if (listener->notify_write) {
    ev.events |= EPOLLOUT;
  }
  return ev;
}

void Add(Listener *listener, Status &status) {
  if (fd == 0) {
    status() += "epoll::Init() was not called";
    return;
  }
  epoll_event ev = MakeEpollEvent(listener);
  if (int r = epoll_ctl(fd, EPOLL_CTL_ADD, listener->fd, &ev); r == -1) {
    status() += "epoll_ctl(EPOLL_CTL_ADD) epfd=" + std::to_string(fd) +
                " fd=" + std::to_string(listener->fd);
    return;
  }
  ++listener_count;
#ifdef DEBUG_EPOLL
  LOG << "Added listener for " << listener->Name() << listener->fd
      << ". Currently " << listener_count << " active listeners.";
#endif
}

void Mod(Listener *listener, Status &status) {
  epoll_event ev = MakeEpollEvent(listener);
#ifdef DEBUG_EPOLL
  LOG << "epoll_ctl " << listener->Name() << listener->fd << " "
      << (ev.events & EPOLLOUT ? "RDWR" : "RD");
#endif
  if (int r = epoll_ctl(fd, EPOLL_CTL_MOD, listener->fd, &ev); r == -1) {
    status() += "epoll_ctl(EPOLL_CTL_MOD)";
  }
}

void Del(Listener *l, Status &status) {
  if (int r = epoll_ctl(fd, EPOLL_CTL_DEL, l->fd, nullptr); r == -1) {
    status() += "epoll_ctl(EPOLL_CTL_DEL)";
    return;
  }
  --listener_count;
  for (int i = 0; i < events_count; ++i) {
    if (events[i].data.ptr == l) {
      events[i].data.ptr = nullptr;
    }
  }
#ifdef DEBUG_EPOLL
  LOG << "Removed listener for " << l->Name() << l->fd << ". Currently "
      << listener_count << " active listeners.";
#endif
}

void Loop(Status &status) {
  for (;;) {
    if (listener_count == 0) {
      break;
    }
    events_count = epoll_wait(fd, events, kMaxEpollEvents, -1);
    if (events_count == -1) {
      if (errno == EINTR) {
        continue;
      }
      status() += "epoll_wait";
      return;
    }

    for (int i = 0; i < events_count; ++i) {
      if (events[i].data.ptr == nullptr)
        continue;
      Listener *l = (Listener *)events[i].data.ptr;
#ifdef DEBUG_EPOLL
      if (strcmp(l->Name(), "Timer")) {
        bool in = events[i].events & EPOLLIN;
        bool out = events[i].events & EPOLLOUT;
        LOG << "epoll_wait[" << i << "/" << events_count << "] " << l->Name()
            << l->fd << " " << (in ? "RD" : "") << (out ? "WR" : "");
      }
#endif
      if (events[i].events & EPOLLIN) {
        l->NotifyRead(status);
        if (!status.Ok()) {
#ifdef DEBUG_EPOLL
          ERROR << l->Name() << ": " << ErrorMessage(status);
#endif
          return;
        }
      }
      if (events[i].data.ptr == nullptr)
        continue;
      if (events[i].events & EPOLLOUT) {
        l->NotifyWrite(status);
        if (!status.Ok()) {
#ifdef DEBUG_EPOLL
          ERROR << l->Name() << ": " << ErrorMessage(status);
#endif
          return;
        }
      }
    }
    events_count = 0;
  }
}

} // namespace maf::epoll
