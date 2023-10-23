#include "dns_server.hh"

#include <sys/socket.h>
#include <unistd.h>

#include "config.hh"
#include "dns_client.hh"
#include "dns_utils.hh"
#include "epoll_udp.hh"
#include "expirable.hh"
#include "log.hh"
#include "status.hh"

using namespace std;
using namespace maf;

namespace maf::dns {

struct ProxyLookup : LookupBase {
  IP client_ip;
  U16 client_port;
  Header header;
  ProxyLookup(IP client_ip, U16 client_port, Message &msg)
      : client_ip(client_ip), client_port(client_port), header(msg.header) {
    ConstructionComplete(msg.questions.front().domain_name,
                         (U16)msg.questions.front().type);
  }

  void OnAnswer(const Message &msg) override;
  void OnExpired() override { delete this; }
};

struct Server : UDPListener {

  // Start listening.
  //
  // To actually accept new connections, make sure to Poll the `epoll`
  // instance after listening.
  void Listen(Status &status) {
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd == -1) {
      AppendErrorMessage(status) += "socket";
      return;
    }

    int flag = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag)) <
        0) {
      AppendErrorMessage(status) += "setsockopt: SO_REUSEADDR";
      StopListening();
      return;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, lan.name.data(),
                   lan.name.size()) < 0) {
      AppendErrorMessage(status) += "Error when setsockopt bind to device";
      StopListening();
      return;
    };

    fd.Bind(INADDR_ANY, kServerPort, status);
    if (!OK(status)) {
      StopListening();
      return;
    }

    epoll::Add(this, status);
  }

  // Stop listening.
  void StopListening() {
    Status ignored;
    epoll::Del(this, ignored);
    shutdown(fd, SHUT_RDWR);
    close(fd);
  }

  Header ResponseHeader(const Message &msg) {
    return Header{
        .id = msg.header.id,
        .recursion_desired = msg.header.recursion_desired,
        .truncated = false,
        .authoritative = false,
        .opcode = msg.header.opcode,
        .reply = true,
        .response_code = ResponseCode::NO_ERROR,
        .reserved = 0,
        .recursion_available = msg.header.recursion_available,
        .question_count = htons(0),
        .answer_count = htons(0),
        .authority_count = htons(0),
        .additional_count = htons(0),
    };
  }

  void SendError(ResponseCode code, const Message &msg, IP client_ip,
                 uint16_t client_port, string &err) {
    Header response = ResponseHeader(msg);
    response.response_code = code;
    fd.SendTo(client_ip, client_port,
              StrView((const char *)(&response), sizeof(response)), err);
  }

  void HandleRequest(string_view buf, IP source_ip,
                     uint16_t source_port) override {
    if (!lan_network.Contains(source_ip)) {
      LOG << "DNS server received a packet from an unexpected source: "
          << source_ip.to_string() << " (expected network " << lan_network
          << ")";
      return;
    }
    Message msg;
    string err;
    msg.Parse(buf.data(), buf.size(), err);
    if (!err.empty()) {
      SendError(ResponseCode::FORMAT_ERROR, msg, source_ip, source_port, err);
      return;
    }

    if (msg.header.opcode == Header::STATUS) {
      // maf's Samsung S10e was observed to send a malformed DNS query for
      // "google.com" with opcode=STATUS & ID=0x0002.
      //
      // Maybe it's some kind of a connectivity probe?
      SendError(ResponseCode::NOT_IMPLEMENTED, msg, source_ip, source_port,
                err);
      return;
    }

    if (msg.header.opcode == Header::IQUERY) {
      // Similarly to the STATUS opcode above, that Android device was also
      // sending IQUERY requests with ID=0x000a & 0x000b for 216.58.202.4 (a
      // Google IP address).
      //
      // IQUERY requests were obsoleted by RFC 3425.
      SendError(ResponseCode::NOT_IMPLEMENTED, msg, source_ip, source_port,
                err);
      return;
    }

    if (msg.header.opcode != Header::QUERY) {
      LOG << "DNS server received a packet with an unsupported opcode: "
          << Header::OperationCodeToString(msg.header.opcode)
          << ". Source: " << source_ip << ". DNS message: " << msg.to_string();
      SendError(ResponseCode::NOT_IMPLEMENTED, msg, source_ip, source_port,
                err);
      return;
    }

    if (msg.questions.size() != 1) {
      LOG << "DNS server expected a packet with exactly one question. "
             "Received: "
          << msg.to_string();
      SendError(ResponseCode::NOT_IMPLEMENTED, msg, source_ip, source_port,
                err);
      return;
    }

    new ProxyLookup(source_ip, source_port, msg);
  }

  void NotifyRead(Status &epoll_status) override {
    Expirable::Expire();
    UDPListener::NotifyRead(epoll_status);
  }

  const char *Name() const override { return "dns::Server"; }
};

Server server;

void ProxyLookup::OnAnswer(const Message &msg) {
  string buffer;
  Header response_header{
      .id = header.id,
      .recursion_desired = true,
      .truncated = false,
      .authoritative = false,
      .opcode = Header::QUERY,
      .reply = true,
      .response_code = msg.header.response_code,
      .reserved = 0,
      .recursion_available = true,
      .question_count = htons(1),
      .answer_count = htons(msg.answers.size()),
      .authority_count = htons(msg.authority.size()),
      .additional_count = htons(msg.additional.size()),
  };
  response_header.write_to(buffer);
  msg.questions.front().write_to(buffer);
  for (auto &a : msg.answers) {
    a.write_to(buffer);
  }
  for (auto &a : msg.authority) {
    a.write_to(buffer);
  }
  for (auto &a : msg.additional) {
    a.write_to(buffer);
  }
  Str err;
  server.fd.SendTo(client_ip, client_port, buffer, err);
  delete this;
}

void StartServer(Status &status) {
  server.Listen(status);
  if (!OK(status)) {
    AppendErrorMessage(status) += "Failed to start DNS server";
    return;
  }
}

void StopServer() { server.StopListening(); }

} // namespace maf::dns
