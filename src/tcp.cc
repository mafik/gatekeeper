#include "tcp.hh"

#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

namespace maf::tcp {

void Server::Listen(Config config) {
  fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
              /*protocol*/ 0);
  if (fd < 0) {
    status() += "socket() failed";
    return;
  }

  if (!config.interface.empty()) {
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, config.interface.data(),
                   config.interface.size()) < 0) {
      status() += "Error when setsockopt bind to device";
      StopListening();
      return;
    };
  }

  int opt = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                 sizeof(opt))) {
    status() += "setsockopt() failed";
    StopListening();
    return;
  }

  fd.Bind(config.local_ip, config.local_port, status);
  if (!OK(status)) {
    StopListening();
    return;
  }

  if (int r = listen(fd, SOMAXCONN); r < 0) {
    status() += "listen() failed";
    StopListening();
    return;
  }

  epoll::Add(this, status);
  if (!status.Ok()) {
    StopListening();
    return;
  }
}

void Server::StopListening() {
  Status ignore;
  epoll::Del(this, ignore);
  shutdown(fd, SHUT_RDWR);
  fd.Close();
}

void Server::NotifyRead(Status &epoll_status) {
  while (status.Ok() && fd != -1) {
    sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    FD conn_fd = accept4(fd, (struct sockaddr *)&addr, &addrlen, SOCK_NONBLOCK);
    if (conn_fd == -1) {
      if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
        // We have processed all incoming connections.
        errno = 0;
        break;
      }
      status() += "accept4()";
      return;
    }
    int opt = 1;
    if (setsockopt(conn_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt))) {
      status() += "setsockopt()";
      return;
    }
    NotifyAcceptedTCP(std::move(conn_fd), IP(addr.sin_addr.s_addr),
                      Big(addr.sin_port).big_endian);
  }
}

const char *Server::Name() const { return "tcp::Server"; }

void Connection::Adopt(FD fd) {
  this->fd = std::move(fd);
  epoll::Add(this, status);
}

void Connection::Connect(Config config) {
  fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    status() += "socket() failed";
    return;
  }

  if (!config.interface.empty()) {
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, config.interface.data(),
                   config.interface.size()) < 0) {
      status() += "Error when setsockopt bind to device";
      return;
    };
  }

  if (config.local_port || config.local_ip.addr) {
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
      status() += "setsockopt(SO_REUSEADDR | SO_REUSEPORT) failed";
      return;
    }
    fd.Bind(config.local_ip, config.local_port, status);
    if (!OK(status)) {
      return;
    }
  }

  sockaddr_in address = {.sin_family = AF_INET,
                         .sin_port = Big(config.remote_port).big_endian,
                         .sin_addr = {.s_addr = config.remote_ip.addr}};
  if (int r = connect(fd, (sockaddr *)&address, sizeof(address)); r < 0) {
    if (errno != EINPROGRESS) {
      status() += "connect() failed";
      return;
    }
  }
  epoll::Add(this, status);
  if (!status.Ok()) {
    status() += "epoll::Add()";
    return;
  }
}

Connection::~Connection() { Close(); }

static void UpdateEpoll(Connection &c) {
  bool current = c.notify_write;
  bool desired = !c.outbox.empty();
  if (current != desired) {
    c.notify_write = desired;
    epoll::Mod(&c, c.status);
  }
}

void Connection::Send() {
  if (fd < 0) {
    return;
  }
  if (outbox.empty()) {
    return;
  }
  if (write_buffer_full) {
    return;
  }
  ssize_t count = send(fd, outbox.data(), outbox.size(), MSG_NOSIGNAL);
  if (count == -1) {
    if (errno == EWOULDBLOCK || errno == EAGAIN) {
      // We must wait for the data to be sent before writing more.
      errno = 0;
      write_buffer_full = true;
      UpdateEpoll(*this);
      return;
    }
    status() += "send()";
    Close();
    return;
  }
  outbox.erase(outbox.begin(), outbox.begin() + count);
  if (closing && outbox.empty()) {
    Close();
    return;
  }
  if (outbox.empty()) {
  } else {
    // Kernel was unable to accept whole buffer - it's probably full.
    write_buffer_full = true;
  }

  UpdateEpoll(*this);
}

void Connection::Close() {
  if (IsClosed()) {
    return;
  }
  epoll::Del(this, status);
  shutdown(fd, SHUT_RDWR);
  fd.Close();
  NotifyClosed();
}

bool Connection::IsClosed() const { return fd == -1; }

thread_local static U8 read_buffer[1024 * 1024];

void Connection::NotifyRead(Status &epoll_status) {
  ssize_t count = read(fd, read_buffer, sizeof(read_buffer));
  if (count == 0) { // EOF
    Close();
    return;
  }
  if (count == -1) {
    if (errno == EWOULDBLOCK) {
      // We must wait for more data to arrive to process this request.
      errno = 0;
      return;
    }
    // Connection is broken. Discard it.
    status() += "read()";
    Close();
    return;
  }

  inbox.insert(inbox.end(), read_buffer, read_buffer + count);
  NotifyReceived();
}

void Connection::NotifyWrite(Status &epoll_status) {
  write_buffer_full = false;
  Send();
}

const char *Connection::Name() const { return "tcp::Connection"; }

} // namespace maf::tcp