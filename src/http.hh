#pragma once

#include "epoll.hh"
#include "ip.hh"

#include <functional>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>

namespace http {

// Request wraps the HTTP request buffer and provides easy access to its
// contents.
struct Request {

  // Reference to the network buffer of the data received from this connection.
  // It may actually contain more requests queued after this one - so be careful
  // to only parse until the first request separator ("\r\n\r\n").
  std::string &buffer;

  // HTTP path.
  //
  // For a request that looks like:
  //  http://www.example.com/questions/3456/my-document?page=10
  // The path will be:
  //  /questions/3456/my-document
  //
  // Note that path is a string_view and refers to the request buffer. You can
  // safely read past its end to access the URL query & HTTP method.
  //
  // See: https://en.wikipedia.org/wiki/URL
  std::string_view path;

  // Mapping of all request headers & their values.
  //
  // All of the values are case-sensitive.
  std::unordered_map<std::string_view, std::string_view> headers;

  // Mapping of all URL query parameters & their values.
  std::unordered_map<std::string_view, std::string_view> query;

  // Constructor parses the provided request buffer & populates all af the
  // convenience variables in this class.
  Request(std::string &request_buffer);

  // Convenient access to the `headers` map.
  std::string_view operator[](std::string_view key);
};

// Wrapper around the HTTP response buffer. Provides methods for easy
// construction of HTTP responses.
struct Response {

  // Reference to the outgoing network buffer for this connection. It may
  // actually contain other (not yet sent) respones before this one - so be
  // careful not to overwrite them!
  std::string &buffer;

  // Flag recording whether the status line for this response has already been
  // written. This ensures that HTTP status line is written only once. It's set
  // by the `WriteStatus` function.
  bool status_written = false;

  // Constructs a Response instance with the given `response_buffer`.
  Response(std::string &response_buffer);

  // Writes the HTTP status code to the response buffer.
  //
  // Status codes look like "200 OK" or "404 Not Found".
  //
  // See: https://datatracker.ietf.org/doc/html/rfc7231#section-6.1
  void WriteStatus(std::string_view status);

  // Appends arbitrary header to the HTTP response.
  void WriteHeader(std::string_view key, std::string_view value);

  // Writes the HTTP response data. This function should be called exactly once
  // for each Response instance.
  void Write(std::string_view data);
};

struct Server;

// Connection stores all of the data related to a single network
// connection.
struct Connection : maf::epoll::Listener {
  // Pointer to the Server instance that this Connection belongs to.
  Server *server;

  // Flag indicating whether this Connection is closed or not.
  bool closed = false;

  // Flag indicating that when all of the data is written, this connection
  // should be closed.
  bool closing = false;

  // Flag indicating whether kernel write buffer is full or not.
  bool write_buffer_full = false;

  // Whether this Connection is listening to write availability notifications
  // from epoll.
  bool listening_to_write_availability = false;

  // Buffer used to store data received from this Connection.
  std::string request_buffer;

  // Buffer used to store data to be sent over this Connection.
  std::string response_buffer;

  // Description of the last error.
  maf::Status status;

  // Textual representation of the remote IP address of this Connection. This
  // comes from the OS network layer. The actual origin IP may be different if
  // this Connection was proxied.
  std::string addr;

  // Flag indicating whether this connection operates in either HTTP or
  // WebSocket mode.
  enum { MODE_HTTP, MODE_WEBSOCKET } mode = MODE_HTTP;

  // Convenience field which allows the users of this library to store arbitrary
  // data in each Connection.
  void *user_data;

  // Send the given payload as a binary WebSocket message.
  void Send(std::string_view payload);

  // Send the given payload as a text WebSocket message.
  void SendText(std::string_view payload);

  // Close this WebSocket connection with an optional code & message.
  void Close(uint16_t code, std::string_view reason);

  // Close the TCP connection that is the base for this Connection.
  //
  // This skips the WebSocket close message.
  void CloseTCP();

  // Reads data whenever it becomes available. Part of the epoll::Listener
  // interface.
  void NotifyRead(maf::Status &) override;

  // Writes data whenever it becomes available. Part of the epoll::Listener
  // interface.
  void NotifyWrite(maf::Status &) override;

  // Part of the epoll::Listener interface.
  const char *Name() const override;
};

// Server stores the data related to a single HTTP(S) server.
//
// Each Server owns a single port. For multi-protocol apps (for example port 80
// + 443), multiple Server instances are required.
//
// In order to accept new connections, receive & send data, epoll::Loop() must
// be called.
struct Server : maf::epoll::Listener {
  // Handler called whenever a HTTP request is made.
  std::function<void(Response &, Request &)> handler;

  // Handler called whenever a new WebSocket connection is created.
  std::function<void(Connection &, Request &)> on_open;

  // Handler called whenever a new WebSocket message arrives.
  std::function<void(Connection &, std::string_view)> on_message;

  // Handler called whenever a WebSocket connection is closed.
  std::function<void(Connection &)> on_close;

  std::set<Connection *> connections;

  // TODO: Max Websocket Payload Length
  // TODO: Max header length
  // TODO: SSL
  // TODO: per message deflate
  // TODO: pings
  // TODO: HTTP fuzz
  // TODO: WebSocket fuzz

  struct Config {
    maf::IP ip = INADDR_ANY;
    uint16_t port = 80;
    std::optional<std::string> interface;
  };

  // Start listening on a given port.
  //
  // To actually accept new connections, make sure to Poll the `epoll`
  // instance after listening.
  void Listen(Config config, maf::Status &);

  // Stop listening.
  void StopListening();

  // Accepts new connection whenever they arrive. Part of the epoll::Listener
  // interface.
  void NotifyRead(maf::Status &) override;

  // Part of the epoll::Listener interface.
  const char *Name() const override;
};

} // namespace http
