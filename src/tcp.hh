#pragma once

#include "epoll.hh"
#include "str.hh"
#include "stream.hh"

namespace maf::tcp {

struct Server : epoll::Listener {
  Status status;

  struct Config {
    Str interface = "";
    IP local_ip = {};
    U16 local_port = 0;
  };

  void Listen(Config);

  void StopListening();

  virtual void NotifyAcceptedTCP(FD, IP, U16 port) = 0;

  /////////////////////////////////////
  // epoll interface - not for users //
  /////////////////////////////////////

  void NotifyRead(Status &) override;

  const char *Name() const override;
};

// Responsible for interacting with the epoll loop.
//
// This is not a "listener" in the TCP sense.
struct Connection : epoll::Listener, Stream {
  // Status of this connection.
  Status status;

  // Flag indicating whether kernel write buffer is full or not.
  //
  // When it's true there is no point in calling `send` because it won't write
  // anything anyway.
  //
  // This flag is cleared by `NotifyWrite` - when kernel notifies us that there
  // is some space in the buffer.
  bool write_buffer_full = false;

  // Flag indicating that when all of the data is written, this connection
  // should be closed.
  //
  // Set it to `true` and call to `SendTCP`. The connection will be closed when
  // all of the data from `send_tcp` is written.
  bool closing = false;

  struct Config : Server::Config {
    IP remote_ip = IP(127, 0, 0, 1);
    U16 remote_port;
  };

  Connection() = default;
  ~Connection();

  void Adopt(FD);
  void Connect(Config);

  void Send() override;
  void Close() override;

  bool IsClosed() const;

  /////////////////////////////////////
  // epoll interface - not for users //
  /////////////////////////////////////

  void NotifyRead(Status &) override;
  void NotifyWrite(Status &) override;

  const char *Name() const override;

  operator Status &() override { return status; }
};

} // namespace maf::tcp