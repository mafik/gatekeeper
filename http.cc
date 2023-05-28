#include "http.hh"
#include "base64.hh"
#include "format.hh"
#include "log.hh"
#include "sha.hh"
#include <arpa/inet.h>
#include <cassert>
#include <cstring>
#include <endian.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

// #define DEBUG_HTTP

namespace http {

const char *kPathAllowedCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO"
                                     "PQRSTUVWXYZ0123456789-._~!$&'()*+,;=:@%/";

Request::Request(std::string &request_buffer) : buffer(request_buffer) {
  size_t method_end = buffer.find(' ');
  if (method_end == std::string::npos) {
    return;
  }
  size_t path_start = method_end + 1;
  size_t path_end =
      buffer.find_first_not_of(kPathAllowedCharacters, path_start);
  if (path_end == std::string::npos) {
    return;
  }
  size_t path_len = path_end - path_start;
  if (path_len > 1024) {
    return;
  }
  path = std::string_view(buffer).substr(path_start, path_len);

  size_t pos = buffer.find("\r\n", path_end);
  if (pos == std::string::npos)
    return;
  while (true) {
    if (buffer.substr(pos, 4) == "\r\n\r\n")
      break;
    size_t key_start = pos + 2;
    if (key_start >= buffer.size())
      break;
    size_t key_end = buffer.find(": ", key_start);
    if (key_end == std::string::npos)
      break;
    size_t val_start = key_end + 2;
    if (val_start >= buffer.size())
      break;
    size_t val_end = buffer.find("\r\n", val_start);
    if (val_end == std::string::npos)
      break;
    std::string_view key(&buffer.data()[key_start], key_end - key_start);
    std::string_view val(&buffer.data()[val_start], val_end - val_start);
    headers[key] = val;
    pos = val_end;
  }
}

std::string_view Request::operator[](std::string_view key) {
  return headers[key];
}

Response::Response(std::string &response_buffer) : buffer(response_buffer) {}

void Response::WriteStatus(std::string_view status) {
  if (status_written)
    return;
  buffer.append("HTTP/1.1 ", 9);
  buffer.append(status);
  buffer.append("\r\n", 2);
  status_written = true;
}

void Response::WriteHeader(std::string_view key, std::string_view value) {
  WriteStatus("200 OK");
  buffer.append(key);
  buffer.append(": ", 2);
  buffer.append(value);
  buffer.append("\r\n", 2);
}

void Response::Write(std::string_view data) {
  WriteHeader("Content-Length", std::to_string(data.size()));
  buffer.append("\r\n", 2);
  buffer.append(data);
}

// returns number of consumed bytes
static int ConsumeWebSocketFrame(Connection &c) {
  if (c.request_buffer.size() < 2)
    return 0;
  bool fin = c.request_buffer[0] >> 7;
  int opcode = c.request_buffer[0] & 15;
  bool mask = c.request_buffer[1] >> 7;
  assert(fin); // TODO: message fragmentation
  uint64_t payload_len = ((int)c.request_buffer[1]) & 127;
  int offset = 2;
  if (payload_len == 126) {
    if (c.request_buffer.size() < 4) // 2 bytes header + 2 bytes payload len
      return 0;
    payload_len = *(uint16_t *)(c.request_buffer.data() + offset);
    offset += 2;
  } else if (payload_len == 127) {
    if (c.request_buffer.size() < 10) // 2 bytes header + 8 bytes of payload len
      return 0;
    payload_len = *(uint64_t *)(c.request_buffer.data() + offset);
    offset += 8;
  }
  if (c.request_buffer.size() < offset + payload_len + (mask ? 4 : 0)) {
    // The frame is still not complete - we must wait for more data to
    // buffer
    return 0;
  }
  char masking_arr[4];
  if (mask) {
    memcpy(masking_arr, c.request_buffer.data() + offset, 4);
    offset += 4;
  }
  char *payload_base = c.request_buffer.data() + offset;
  for (int i = 0; i < payload_len; ++i) {
    payload_base[i] ^= masking_arr[i % 4];
  }
  std::string_view sv(payload_base, payload_len);

  if (opcode == 2 && c.server->on_message) {
    c.server->on_message(c, sv);
  }
  if (opcode == 8) {
    c.CloseTCP();
  }

  return offset + payload_len;
}

// Returns number of consumed bytes
static int ConsumeHttpRequest(Connection &c) {
  const char *kRequestHeaderEnding = "\r\n\r\n";
  size_t pos = c.request_buffer.find(kRequestHeaderEnding);
  if (pos == std::string::npos) {
    // We must read more data to get the full header.
#ifdef DEBUG_HTTP
    LOG << " -> waiting for more data (end of request not found)";
#endif
    return 0;
  }

  Response response(c.response_buffer);
  Request request(c.request_buffer);

  bool connection_header = request["Connection"] == "Upgrade";
  bool upgrade_header = request["Upgrade"] == "websocket";
  std::string_view websocket_key = request["Sec-WebSocket-Key"];
  if (connection_header && upgrade_header && !websocket_key.empty()) {
    std::string sha_buf;
    sha_buf += websocket_key;
    sha_buf += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    auto sha_sum = SHA1(sha_buf);
    auto sha_b64 = Base64Encode(sha_sum);

    response.WriteStatus("101 Switching Protocols");
    response.WriteHeader("Upgrade", "websocket");
    response.WriteHeader("Connection", "Upgrade");
    response.WriteHeader("Sec-WebSocket-Accept", sha_b64);
    auto protocol = request["Sec-WebSocket-Protocol"];
    response.WriteHeader("Sec-WebSocket-Protocol", protocol);
    c.response_buffer += "\r\n";
#ifdef DEBUG_HTTP
    LOG << " -> websocket upgrade";
#endif
    c.mode = Connection::MODE_WEBSOCKET;
    if (c.server->on_open) {
      c.server->on_open(c, request);
    }
  } else {
#ifdef DEBUG_HTTP
    LOG << " -> HTTP request: " << request.path;
#endif
    c.server->handler(response, request);
  }

  return pos + strlen(kRequestHeaderEnding);
}

static void UpdateEpoll(Connection &c) {
  bool &current = c.listening_to_write_availability;
  bool desired = c.ListenWriteAvailability();
  if (current != desired) {
    epoll::Mod(&c, c.error);
    current = desired;
  }
}

static void TryWriting(Connection &c) {
  if (c.closed) {
    return;
  }
  if (c.response_buffer.empty()) {
    return;
  }
  if (c.write_buffer_full) {
    return;
  }
  ssize_t count = send(c.fd, c.response_buffer.c_str(),
                       c.response_buffer.size(), MSG_NOSIGNAL);
#ifdef DEBUG_HTTP
  LOG << "write " << c.fd << ": " << (int)count << "bytes";
#endif
  if (count == -1) {
    if (errno == EWOULDBLOCK || errno == EAGAIN) {
      // We must wait for the data to be sent before writing more.
      c.write_buffer_full = true;
#ifdef DEBUG_HTTP
      LOG << " -> waiting to send more data (EWOULDBLOCK)";
#endif
      UpdateEpoll(c);
      return;
    }
    c.error = "send(): ";
    c.error += strerror(errno);
    c.CloseTCP();
#ifdef DEBUG_HTTP
    LOG << " -> closing (ERROR)";
#endif
    return;
  }
  c.response_buffer = c.response_buffer.substr(count);
  if (c.closing && c.response_buffer.empty()) {
#ifdef DEBUG_HTTP
    LOG << " -> closing (shutting down & fully DRAINED)";
#endif
    c.CloseTCP();
    return;
  }
  if (c.response_buffer.empty()) {
#ifdef DEBUG_HTTP
    LOG << " -> all data sent!";
#endif
  } else {
    // Kernel was unable to accept whole buffer - it's probably full.
    c.write_buffer_full = true;
#ifdef DEBUG_HTTP
    LOG << " -> more data to send...";
#endif
  }

  UpdateEpoll(c);
}

static char read_buffer[1024 * 1024];

static void TryReading(Connection &c) {
  ssize_t count = read(c.fd, read_buffer, sizeof(read_buffer));
#ifdef DEBUG_HTTP
  LOG << "read fd=" << c.fd << ", returned " << (int)count
      << " bytes, buffer size=" << (int)(c.request_buffer.size() + count)
      << " bytes";
#endif
  if (count == 0) { // EOF
#ifdef DEBUG_HTTP
    LOG << " -> closing (EOF)";
#endif
    c.CloseTCP();
    return;
  }
  if (count == -1) {
    if (errno == EWOULDBLOCK) {
      // We must wait for more data to arrive to process this request.
#ifdef DEBUG_HTTP
      LOG << " -> waiting for more data (EWOULDBLOCK)";
#endif
      return;
    }
    // Connection is broken. Discard it.
#ifdef DEBUG_HTTP
    LOG << " -> closing (ERROR)";
#endif
    c.error = "read(): ";
    c.error += strerror(errno);
    c.CloseTCP();
    return;
  }
  c.request_buffer.append(read_buffer, count);
  if (c.mode == Connection::MODE_HTTP) {
    while (int consumed_bytes = ConsumeHttpRequest(c)) {
      c.request_buffer = c.request_buffer.substr(consumed_bytes);
    }
    if (!c.request_buffer.empty()) {
      LOG << "Request buffer is not empty after request has been consumed!";
    }
  } else if (c.mode == Connection::MODE_WEBSOCKET) {
#ifdef DEBUG_HTTP
    LOG << " -> WebSocket frame";
#endif
    while (int consumed_bytes = ConsumeWebSocketFrame(c)) {
      c.request_buffer = c.request_buffer.substr(consumed_bytes);
    }
  }
  TryWriting(c);
}

static void AppendWebSocketFrame(Connection &c, uint8_t opcode,
                                 std::string_view payload) {
  char header[10];
  int header_size;
  header[0] = (char)(1 << 7 | opcode); // FIN | opcode
  uint64_t len = payload.size();
  if (len < 126) {
    header_size = 2;
    header[1] = (char)len;
  } else if (len < 0x10000) {
    header_size = 4;
    header[1] = 126;
    *(uint16_t *)(header + 2) = htobe16(len);
  } else {
    header_size = 10;
    header[1] = 127;
    *(uint64_t *)(header + 2) = htobe64(len);
  }
  c.response_buffer.append(header, header_size);
  c.response_buffer.append(payload);
  TryWriting(c);
}

void Connection::Send(std::string_view payload) {
  AppendWebSocketFrame(*this, 2, payload);
}

void Connection::Close(uint16_t code, std::string_view reason) {
  assert(mode == MODE_WEBSOCKET);
  char payload[reason.size() + 2];
  *(uint16_t *)(payload) = htobe16(code);
  memcpy(payload + 2, reason.data(), reason.size());
  closing = true;
  AppendWebSocketFrame(*this, 8, std::string_view(payload, reason.size() + 2));
}

void Connection::CloseTCP() {
  closed = true;
  epoll::Del(this, error);
  close(fd);
}

bool Connection::ListenWriteAvailability() { return !response_buffer.empty(); }

void Connection::NotifyRead(std::string &error) {
  TryReading(*this);
  if (!this->error.empty()) {
    LOG << "Connection error: " << this->error;
  }
  if (closed) {
    if (mode == MODE_WEBSOCKET && server->on_close) {
      server->on_close(*this);
    }
    server->connections.erase(this);
    delete this;
  }
}

void Connection::NotifyWrite(std::string &error) {
  write_buffer_full = false;
  TryWriting(*this);
  if (!this->error.empty()) {
    LOG << "Connection error: " << this->error;
  }
  if (closed) {
    if (mode == MODE_WEBSOCKET && server->on_close) {
      server->on_close(*this);
    }
    server->connections.erase(this);
    delete this;
  }
}

const char *Connection::Name() const { return "Connection"; }

void Server::Listen(Config config, std::string &error) {
  fd = socket(AF_INET, SOCK_STREAM, /*protocol*/ 0);
  if (fd == 0) {
    error = "socket() failed";
    return;
  }

  int flags = fcntl(fd, F_GETFL);
  if (flags < 0) {
    error = "fcntl(F_GETFL) failed";
    StopListening();
    return;
  }

  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    error = "fcntl(F_SETFL) failed";
    StopListening();
    return;
  }

  int opt = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                 sizeof(opt))) {
    error = "setsockopt() failed";
    StopListening();
    return;
  }

  if (config.interface.has_value()) {
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, config.interface->data(),
                   config.interface->size()) < 0) {
      error = "Error when setsockopt bind to device";
      StopListening();
      return;
    };
  }

  sockaddr_in address = {.sin_family = AF_INET,
                         .sin_port = htons(config.port),
                         .sin_addr = {.s_addr = config.ip.addr}};
  if (int r = bind(fd, (sockaddr *)&address, sizeof(address)); r < 0) {
    error = "bind() failed";
    StopListening();
    return;
  }

  if (int r = listen(fd, SOMAXCONN); r < 0) {
    error = "listen() failed";
    StopListening();
    return;
  }

  epoll::Add(this, error);
  if (!error.empty()) {
    StopListening();
    return;
  }
}

void Server::StopListening() {
  std::string error_ignored;
  epoll::Del(this, error_ignored);
  shutdown(fd, SHUT_RDWR);
  close(fd);
}

void Server::NotifyRead(std::string &error) {
  while (true) {
    sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int conn_fd =
        accept4(fd, (struct sockaddr *)&addr, &addrlen, SOCK_NONBLOCK);
    if (conn_fd == -1) {
      if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
        // We have processed all incoming connections.
        break;
      }
      error = "accept() failed";
      return;
    }
    int opt = 1;
    if (setsockopt(conn_fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt))) {
      error = "setsockopt() failed";
      return;
    }
    Connection *conn = new Connection();
    connections.insert(conn);
    conn->server = this;
    conn->fd = conn_fd;
    char addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), addr_str, INET_ADDRSTRLEN);
    conn->addr = addr_str;
#ifdef DEBUG_HTTP
    LOG << "accept " << conn_fd;
#endif
    epoll::Add(conn, error);
    conn->NotifyRead(error);
  }
}

const char *Server::Name() const { return "Server"; }

} // namespace http

// TODO: TCP_NODELAY
