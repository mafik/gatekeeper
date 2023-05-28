#include "epoll.hh"
#include "log.hh"
#include <cassert>
#include <cerrno>
#include <cstring>
#include <sys/epoll.h>

// Build for: HYPERDECK_SERVER

// #define DEBUG_EPOLL

namespace epoll {

bool Listener::ListenReadAvailability() { return true; }
bool Listener::ListenWriteAvailability() { return false; }

int fd;
int listener_count = 0;

static constexpr int kMaxEpollEvents = 10;
static epoll_event events[kMaxEpollEvents];
static int events_count = 0;

void Init() { fd = epoll_create1(0); }

static epoll_event MakeEpollEvent(Listener *listener) {
  epoll_event ev = {.events = EPOLLET, .data = {.ptr = listener}};
  if (listener->ListenReadAvailability()) {
    ev.events |= EPOLLIN;
  }
  if (listener->ListenWriteAvailability()) {
    ev.events |= EPOLLOUT;
  }
  return ev;
}


void Add(Listener *listener, std::string &error) {
  epoll_event ev = MakeEpollEvent(listener);
  if (int r = epoll_ctl(fd, EPOLL_CTL_ADD, listener->fd, &ev);
      r == -1) {
    error = "epoll_ctl(EPOLL_CTL_ADD): ";
    error += strerror(errno);
    return;
  }
  ++listener_count;
#ifdef DEBUG_EPOLL
  LOG << "Added listener for " << listener->Name() << listener->fd << ". Currently " << listener_count << " active listeners.";
#endif
}

void Mod(Listener *listener, std::string &error) {
  epoll_event ev = MakeEpollEvent(listener);
#ifdef DEBUG_EPOLL
  LOG << "epoll_ctl " << listener->Name() << listener->fd << " " << (ev.events & EPOLLOUT ? "RDWR" : "RD");
#endif
  if (int r = epoll_ctl(fd, EPOLL_CTL_MOD, listener->fd, &ev);
      r == -1) {
    error = "epoll_ctl(EPOLL_CTL_MOD): ";
    error += strerror(errno);
  }
}

void Del(Listener *l, std::string &error) {
  if (int r = epoll_ctl(fd, EPOLL_CTL_DEL, l->fd, nullptr); r == -1) {
    error = "epoll_ctl(EPOLL_CTL_DEL): ";
    error += strerror(errno);
    return;
  }
  --listener_count;
  for (int i = 0; i < events_count; ++i) {
    if (events[i].data.ptr == l) {
      events[i].data.ptr = nullptr;
    }
  }
#ifdef DEBUG_EPOLL
  LOG << "Removed listener for " << l->Name() << l->fd << ". Currently " << listener_count << " active listeners.";
#endif
}

void Loop(std::string &error) {
  for (;;) {
    if (listener_count == 0) {
      break;
    }
    events_count = epoll_wait(fd, events, kMaxEpollEvents, -1);
    if (events_count == -1) {
      if (errno == EINTR) {
        continue;
      }
      error = "epoll_wait: ";
      error += strerror(errno);
      return;
    }

    for (int i = 0; i < events_count; ++i) {
      Listener *l = (Listener *)events[i].data.ptr;
      if (events[i].data.ptr == nullptr) continue;
#ifdef DEBUG_EPOLL
      if (strcmp(l->Name(), "Timer")) {
        bool in = events[i].events & EPOLLIN;
        bool out = events[i].events & EPOLLOUT;
        LOG << "epoll_wait[" << i << "/" << events_count << "] " << l->Name() << l->fd << " " << (in ? "RD" : "") << (out ? "WR" : "");
      }
#endif
      if (events[i].events & EPOLLIN) {
        l->NotifyRead(error);
        if (!error.empty()) {
          return;
        }
      }
      if (events[i].data.ptr == nullptr) continue;
      if (events[i].events & EPOLLOUT) {
        l->NotifyWrite(error);
        if (!error.empty()) {
          return;
        }
      }
    }
    events_count = 0;
  }
}

} // namespace epoll
