#include "dns.hh"

#include <map>
#include <unistd.h>
#include <unordered_set>

#include "chrono.hh"
#include "config.hh"
#include "epoll_udp.hh"
#include "etc.hh"
#include "format.hh"
#include "hex.hh"
#include "log.hh"
#include "random.hh"
#include "status.hh"

using namespace std;
using namespace maf;

namespace dns {

static constexpr uint16_t kServerPort = 53;
static constexpr steady_clock::duration kAuthoritativeTTL = 60s;
static constexpr steady_clock::duration kPendingTTL = 20s;

string TypeToString(Type t) {
  switch (t) {
  case Type::A:
    return "A";
  case Type::NS:
    return "NS";
  case Type::CNAME:
    return "CNAME";
  case Type::SOA:
    return "SOA";
  case Type::PTR:
    return "PTR";
  case Type::MX:
    return "MX";
  case Type::TXT:
    return "TXT";
  case Type::AAAA:
    return "AAAA";
  case Type::SRV:
    return "SRV";
  case Type::HTTPS:
    return "HTTPS";
  case Type::ANY:
    return "ANY";
  default:
    return f("UNKNOWN(%hu)", t);
  }
}

string ClassToString(Class c) {
  switch (c) {
  case Class::IN:
    return "IN";
  case Class::ANY:
    return "ANY";
  default:
    return f("UNKNOWN(%hu)", c);
  }
}

pair<string, size_t> LoadDomainName(const char *dns_message_base,
                                    size_t dns_message_len, size_t offset) {
  size_t start_offset = offset;
  string domain_name;
  while (true) {
    if (offset >= dns_message_len) {
      return make_pair("", 0);
    }
    char n = dns_message_base[offset++];
    if (n == 0) {
      return make_pair(domain_name, offset - start_offset);
    }
    if ((n & 0b1100'0000) == 0b1100'0000) { // DNS compression
      if (offset >= dns_message_len) {
        return make_pair("", 0);
      }
      uint16_t new_offset =
          ((n & 0b0011'1111) << 8) | dns_message_base[offset++];
      if (new_offset >=
          start_offset) { // disallow forward jumps to avoid infinite loops
        return make_pair("", 0);
      }
      auto [suffix, suffix_bytes] =
          LoadDomainName(dns_message_base, dns_message_len, new_offset);
      if (suffix_bytes == 0) {
        return make_pair("", 0);
      }
      if (!domain_name.empty()) {
        domain_name += '.';
      }
      domain_name += suffix;
      return make_pair(domain_name, offset - start_offset);
    }
    if (offset + n > dns_message_len) {
      return make_pair("", 0);
    }
    if (!domain_name.empty()) {
      domain_name += '.';
    }
    domain_name.append((char *)dns_message_base + offset, n);
    offset += n;
  }
}

string EncodeDomainName(const string &domain_name) {
  string buffer;
  size_t seg_begin = 0;
encode_segment:
  size_t seg_end = domain_name.find('.', seg_begin);
  if (seg_end == -1)
    seg_end = domain_name.size();
  size_t n = seg_end - seg_begin;
  if (n) { // don't encode 0-length segments - because \0 marks the end of
           // domain name
    buffer.append({(char)n});
    buffer.append(domain_name, seg_begin, n);
  }
  if (seg_end < domain_name.size()) {
    seg_begin = seg_end + 1;
    goto encode_segment;
  }
  buffer.append({0});
  return buffer;
}

struct SOA {
  string primary_name_server;
  string mailbox;
  uint32_t serial_number;
  uint32_t refresh_interval;
  uint32_t retry_interval;
  uint32_t expire_limit;
  uint32_t minimum_ttl;

  size_t LoadFrom(const char *ptr, size_t len, size_t offset) {
    size_t start_offset = offset;
    size_t loaded_size;
    tie(primary_name_server, loaded_size) = LoadDomainName(ptr, len, offset);
    if (loaded_size == 0) {
      return 0;
    }
    offset += loaded_size;
    tie(mailbox, loaded_size) = LoadDomainName(ptr, len, offset);
    if (loaded_size == 0) {
      return 0;
    }
    offset += loaded_size;
    if (offset + 20 > len) {
      return 0;
    }
    serial_number = ntohl(*(uint32_t *)(ptr + offset));
    offset += 4;
    refresh_interval = ntohl(*(uint32_t *)(ptr + offset));
    offset += 4;
    retry_interval = ntohl(*(uint32_t *)(ptr + offset));
    offset += 4;
    expire_limit = ntohl(*(uint32_t *)(ptr + offset));
    offset += 4;
    minimum_ttl = ntohl(*(uint32_t *)(ptr + offset));
    offset += 4;
    return offset - start_offset;
  }
  void write_to(string &buffer) const {
    buffer += EncodeDomainName(primary_name_server);
    buffer += EncodeDomainName(mailbox);
    uint32_t serial_number_big_endian = htonl(serial_number);
    buffer.append((char *)&serial_number_big_endian,
                  sizeof(serial_number_big_endian));
    uint32_t refresh_interval_big_endian = htonl(refresh_interval);
    buffer.append((char *)&refresh_interval_big_endian,
                  sizeof(refresh_interval_big_endian));
    uint32_t retry_interval_big_endian = htonl(retry_interval);
    buffer.append((char *)&retry_interval_big_endian,
                  sizeof(retry_interval_big_endian));
    uint32_t expire_limit_big_endian = htonl(expire_limit);
    buffer.append((char *)&expire_limit_big_endian,
                  sizeof(expire_limit_big_endian));
    uint32_t minimum_ttl_big_endian = htonl(minimum_ttl);
    buffer.append((char *)&minimum_ttl_big_endian,
                  sizeof(minimum_ttl_big_endian));
  }
};

const char *ResponseCodeToString(ResponseCode code) {
  switch (code) {
  case ResponseCode::NO_ERROR:
    return "NO_ERROR";
  case ResponseCode::FORMAT_ERROR:
    return "FORMAT_ERROR";
  case ResponseCode::SERVER_FAILURE:
    return "SERVER_FAILURE";
  case ResponseCode::NAME_ERROR:
    return "NAME_ERROR";
  case ResponseCode::NOT_IMPLEMENTED:
    return "NOT_IMPLEMENTED";
  case ResponseCode::REFUSED:
    return "REFUSED";
  default:
    return "UNKNOWN";
  }
}

static_assert(sizeof(Header) == 12, "dns::Header is not packed correctly");

struct Entry;
void AnswerRequest(const IncomingRequest &request, const Entry &e, string &err);

struct QuestionHash {
  using is_transparent = std::true_type;

  size_t operator()(const Question &q) const {
    return hash<string>()(q.domain_name) ^ hash<Type>()(q.type) ^
           hash<Class>()(q.class_);
  }
  size_t operator()(const Entry &e) const { return (*this)(e.question); }
  size_t operator()(const Entry *e) const { return (*this)(*e); }
};

struct QuestionEqual {
  using is_transparent = std::true_type;

  bool operator()(const Entry &a, const Entry &b) const {
    return a.question == b.question;
  }
  bool operator()(const Entry *a, const Entry *b) const {
    return a->question == b->question;
  }
  bool operator()(const Question &a, const Entry &b) const {
    return a == b.question;
  }
  bool operator()(const Question &a, const Entry *b) const {
    return a == b->question;
  }
};

unordered_set<const Entry *, QuestionHash, QuestionEqual> cache;

unordered_set<Entry, QuestionHash, QuestionEqual> static_cache;

multimap<steady_clock::time_point, const Entry *> expiration_queue;

void Entry::UpdateExpiration(steady_clock::time_point new_expiration) const {
  if (expiration) {
    auto [begin, end] = expiration_queue.equal_range(*expiration);
    for (auto it = begin; it != end; ++it) {
      if (it->second == this) {
        expiration_queue.erase(it);
        break;
      }
    }
  }
  expiration = new_expiration;
  expiration_queue.emplace(new_expiration, this);
}

void ExpireEntries() {
  auto now = steady_clock::now();
  while (!expiration_queue.empty() && expiration_queue.begin()->first < now) {
    LOG << "Expiring " << expiration_queue.begin()->second->question.to_html();
    cache.erase(expiration_queue.begin()->second);
    expiration_queue.erase(expiration_queue.begin());
  }
}

const Entry *GetCachedEntry(const Question &question) {
  if (question.domain_name.ends_with("." + kLocalDomain)) {
    auto it = static_cache.find(question);
    if (it != static_cache.end()) {
      it->expiration = steady_clock::now() + 1h;
      return &*it;
    }
    static Entry name_not_found_entry =
        Entry{.state = Entry::Ready{ResponseCode::NAME_ERROR, {}}};
    name_not_found_entry.question = question;
    name_not_found_entry.expiration = steady_clock::now() + 60s;
    return &name_not_found_entry;
  } else {
    auto it = cache.find(question);
    if (it == cache.end()) {
      return nullptr;
    }
    return *it;
  }
}

struct Client : UDPListener {
  uint16_t request_id;
  int server_i = 0;

  uint16_t AllocateRequestId() {
    return request_id = htons(ntohs(request_id) + 1);
  }

  void Listen(Status &status) {
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
      AppendErrorMessage(status) += "socket";
      return;
    }

    fd.SetNonBlocking(status);
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

  void HandleRequest(string_view buf, IP source_ip,
                     uint16_t source_port) override {
    if (find(etc::resolv.begin(), etc::resolv.end(), source_ip) ==
        etc::resolv.end()) {
      string dns_servers = "";
      for (const auto &server : etc::resolv) {
        if (!dns_servers.empty()) {
          dns_servers += " / ";
        }
        dns_servers += server.to_string();
      }
      LOG << "DNS client received a packet from an unexpected source: "
          << source_ip.to_string() << " (expected: " << dns_servers << ")";
      return;
    }
    if (source_port != kServerPort) {
      LOG << "DNS client received a packet from an unexpected source port: "
          << source_port << " (expected port " << kServerPort << ")";
      return;
    }
    Message msg;
    string err;
    msg.Parse(buf.data(), buf.size(), err);
    if (!err.empty()) {
      ERROR << err;
      return;
    }

    if (msg.header.opcode != Header::QUERY) {
      LOG << "DNS client received a packet with an unsupported opcode: "
          << Header::OperationCodeToString(msg.header.opcode)
          << ". Full query: " << msg.header.to_string();
      return;
    }

    if (!msg.header.reply) {
      LOG << "DNS client received a packet that is not a reply: "
          << msg.header.to_string();
      return;
    }

    const Entry *entry = GetCachedEntry(msg.question);
    if (entry == nullptr) {
      LOG << "DNS client received an unexpected / expired reply: "
          << msg.question.to_string();
      return;
    }
    entry->HandleAnswer(msg, err);
    if (!err.empty()) {
      ERROR << err;
      return;
    }
  }

  void NotifyRead(Status &epoll_status) override {
    ExpireEntries();
    UDPListener::NotifyRead(epoll_status);
  }

  const Entry &GetCachedEntryOrSendRequest(const Question &question,
                                           string &err) {
    const Entry *entry = GetCachedEntry(question);
    if (entry == nullptr) {
      // Send a request to the upstream DNS server.
      uint16_t id = AllocateRequestId();
      Entry *new_entry = new Entry{
          .question = question,
          .expiration = steady_clock::now() + kPendingTTL,
          .state = Entry::Pending{id, {}},
      };
      new_entry->UpdateExpiration(steady_clock::now() + kPendingTTL);
      entry = new_entry;
      cache.insert(entry);
      string buffer;
      Header{.id = id, .recursion_desired = true, .question_count = htons(1)}
          .write_to(buffer);
      question.write_to(buffer);
      IP upstream_ip =
          etc::resolv[(++server_i) % etc::resolv.size()]; // Round-robin
      fd.SendTo(upstream_ip, kServerPort, buffer, err);
      if (err.empty()) {
        LOG << f("Forwarding %s.", question.to_html().c_str());
      }
    }
    return *entry;
  }

  const char *Name() const override { return "dns::Client"; }
};

Client client;

struct Server : UDPListener {

  // Start listening.
  //
  // To actually accept new connections, make sure to Poll the `epoll`
  // instance after listening.
  void Listen(Status &status) {
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
      AppendErrorMessage(status) += "socket";
      return;
    }

    fd.SetNonBlocking(status);
    if (!OK(status)) {
      StopListening();
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
      ERROR << err;
      return;
    }

    if (msg.header.opcode != Header::QUERY) {
      LOG << "DNS server received a packet with an unsupported opcode: "
          << Header::OperationCodeToString(msg.header.opcode)
          << ". Full query: " << msg.header.to_string();
      return;
    }

    LOG << f("#%04hx %s:%hu Asks for %s", msg.header.id,
             source_ip.to_string().c_str(), source_port,
             msg.question.to_html().c_str());

    const Entry &entry = client.GetCachedEntryOrSendRequest(msg.question, err);
    if (!err.empty()) {
      ERROR << err;
      return;
    }
    entry.HandleIncomingRequest(IncomingRequest{
        .header = msg.header,
        .client_ip = source_ip,
        .client_port = source_port,
    });
  }

  void NotifyRead(Status &epoll_status) override {
    ExpireEntries();
    UDPListener::NotifyRead(epoll_status);
  }

  const char *Name() const override { return "dns::Server"; }
};

Server server;

void AnswerRequest(const IncomingRequest &request, const Entry &e,
                   string &err) {
  const Entry::Ready *r = get_if<Entry::Ready>(&e.state);
  if (r == nullptr) {
    err = "AnswerRequest called on an entry that is not ready";
    return;
  }
  string buffer;
  Header response_header{
      .id = request.header.id,
      .recursion_desired = true,
      .truncated = false,
      .authoritative = false,
      .opcode = Header::QUERY,
      .reply = true,
      .response_code = r->response_code,
      .reserved = 0,
      .recursion_available = true,
      .question_count = htons(1),
      .answer_count = htons(r->answers.size()),
      .authority_count = htons(r->authority.size()),
      .additional_count = htons(r->additional.size()),
  };
  response_header.write_to(buffer);
  e.question.write_to(buffer);
  for (auto &a : r->answers) {
    a.write_to(buffer);
  }
  for (auto &a : r->authority) {
    a.write_to(buffer);
  }
  for (auto &a : r->additional) {
    a.write_to(buffer);
  }
  server.fd.SendTo(request.client_ip, request.client_port, buffer, err);
}

void InjectAuthoritativeEntry(const string &domain, IP ip) {
  string encoded_domain = EncodeDomainName(domain);
  static_cache.insert(Entry{
      .question = Question{.domain_name = domain},
      .expiration = std::nullopt,
      .state = Entry::Ready{
          .response_code = ResponseCode::NO_ERROR,
          .answers = {Record{Question{.domain_name = domain}, kAuthoritativeTTL,
                             (uint16_t)sizeof(ip.addr),
                             string((char *)&ip.addr, sizeof(ip.addr))}}}});
}

void Start(Status &status) {
  client.request_id = random<uint16_t>(); // randomize initial request ID

  for (auto &[ip, aliases] : etc::hosts) {
    if (ip.bytes[0] == 127) {
      continue;
    }
    for (auto &alias : aliases) {
      string domain = alias + "." + kLocalDomain;
      InjectAuthoritativeEntry(domain, ip);
    }
  }
  InjectAuthoritativeEntry(etc::hostname + "." + kLocalDomain, lan_ip);
  client.Listen(status);
  if (!OK(status)) {
    AppendErrorMessage(status) += "Failed to start DNS client";
    return;
  }
  server.Listen(status);
  if (!OK(status)) {
    AppendErrorMessage(status) += "Failed to start DNS server";
    return;
  }
}

size_t Question::LoadFrom(const char *ptr, size_t len, size_t offset) {
  size_t start_offset = offset;
  auto [loaded_name, loaded_size] = LoadDomainName(ptr, len, offset);
  if (loaded_size == 0) {
    return 0;
  }
  domain_name = loaded_name;
  offset += loaded_size;
  if (offset + 4 > len) {
    return 0;
  }
  type = Type(ntohs(*(uint16_t *)(ptr + offset)));
  offset += 2;
  class_ = Class(ntohs(*(uint16_t *)(ptr + offset)));
  offset += 2;
  return offset - start_offset;
}
void Question::write_to(string &buffer) const {
  string encoded = EncodeDomainName(domain_name);
  buffer.append(encoded);
  uint16_t type_big_endian = htons((uint16_t)type);
  buffer.append((char *)&type_big_endian, 2);
  uint16_t class_big_endian = htons((uint16_t)class_);
  buffer.append((char *)&class_big_endian, 2);
}
string Question::to_string() const {
  return "dns::Question(" + domain_name + ", type=" + TypeToString(type) +
         ", class=" + string(ClassToString(class_)) + ")";
}
bool Question::operator==(const Question &other) const {
  return (domain_name == other.domain_name) && (type == other.type) &&
         (class_ == other.class_);
}
string Question::to_html() const {
  return "<code class=dns-question>" + domain_name + " " + TypeToString(type) +
         "</code>";
}
size_t Record::LoadFrom(const char *ptr, size_t len, size_t offset) {
  size_t start_offset = offset;
  size_t base_size = Question::LoadFrom(ptr, len, offset);
  if (base_size == 0) {
    return 0;
  }
  offset += base_size;
  if (offset + 6 > len) {
    return 0;
  }
  expiration = steady_clock::now() +
               chrono::seconds(ntohl(*(uint32_t *)(ptr + offset))) +
               chrono::milliseconds(500);
  offset += 4;
  data_length = ntohs(*(uint16_t *)(ptr + offset));
  offset += 2;
  if (offset + data_length > len) {
    return 0;
  }
  if (type == Type::CNAME) {
    size_t limited_len = offset + data_length;
    auto [loaded_name, loaded_size] = LoadDomainName(ptr, limited_len, offset);
    if (loaded_size == 0) {
      return 0;
    }
    if (loaded_size != data_length) {
      return 0;
    }
    offset += data_length;
    // Re-encode domain name but without DNS compression
    data = EncodeDomainName(loaded_name);
    data_length = data.size();
  } else if (type == Type::SOA) {
    size_t limited_len = offset + data_length;
    SOA soa;
    size_t soa_len = soa.LoadFrom(ptr, limited_len, offset);
    if (soa_len != data_length) {
      return 0;
    }
    offset += data_length;
    // Re-encode SOA record but without DNS compression
    data = "";
    soa.write_to(data);
  } else {
    data = string((const char *)(ptr + offset), data_length);
    offset += data_length;
  }
  return offset - start_offset;
}
void Record::write_to(string &buffer) const {
  Question::write_to(buffer);
  uint32_t ttl_big_endian = htonl(ttl());
  buffer.append((char *)&ttl_big_endian, sizeof(ttl_big_endian));
  uint16_t data_length_big_endian = htons(data_length);
  buffer.append((char *)&data_length_big_endian,
                sizeof(data_length_big_endian));
  buffer.append(data);
}
uint32_t Record::ttl() const {
  return visit(
      overloaded{
          [&](steady_clock::time_point expiration) {
            auto d =
                duration_cast<chrono::seconds>(expiration - steady_clock::now())
                    .count();
            return (uint32_t)max(d, 0l);
          },
          [&](steady_clock::duration expiration) {
            return (uint32_t)duration_cast<chrono::seconds>(expiration).count();
          },
      },
      expiration);
}
string Record::to_string() const {
  return "dns::Record(" + Question::to_string() +
         ", ttl=" + std::to_string(ttl()) + ", data=\"" + BytesToHex(data) +
         "\")";
}
string Record::pretty_value() const {
  if (type == Type::A) {
    if (data.size() == 4) {
      return std::to_string((uint8_t)data[0]) + "." +
             std::to_string((uint8_t)data[1]) + "." +
             std::to_string((uint8_t)data[2]) + "." +
             std::to_string((uint8_t)data[3]);
    }
  } else if (type == Type::CNAME) {
    auto [loaded_name, loaded_size] =
        LoadDomainName(data.data(), data.size(), 0);
    if (loaded_size == data.size()) {
      return loaded_name;
    }
  } else if (type == Type::SOA) {
    SOA soa;
    size_t parsed = soa.LoadFrom(data.data(), data.size(), 0);
    if (parsed == data.size()) {
      return f("%s %s %d %d %d %d %d", soa.primary_name_server.c_str(),
               soa.mailbox.c_str(), soa.serial_number, soa.refresh_interval,
               soa.retry_interval, soa.expire_limit, soa.minimum_ttl);
    }
  }
  return BytesToHex(data);
}
string Record::to_html() const {
  return "<code class=dns-record title=TTL=" + std::to_string(ttl()) +
         "s style=display:inline-block>" + domain_name + " " +
         TypeToString(type) + " " + pretty_value() + "</code>";
}
string Entry::Ready::to_string() const {
  string r = "Ready(" + string(ResponseCodeToString(response_code));
  for (const Record &a : answers) {
    r += "  " + a.to_string();
  }
  for (const Record &a : authority) {
    r += "  " + a.to_string();
  }
  for (const Record &a : additional) {
    r += "  " + a.to_string();
  }
  r += ")";
  return r;
}
string Entry::Ready::to_html() const {
  string r = "<code>" + string(ResponseCodeToString(response_code)) + "</code>";
  for (const Record &a : answers) {
    r += " " + a.to_html();
  }
  for (const Record &a : authority) {
    r += " " + a.to_html();
  }
  for (const Record &a : additional) {
    r += " " + a.to_html();
  }
  return r;
}
string Header::OperationCodeToString(OperationCode code) {
  switch (code) {
  case QUERY:
    return "QUERY";
  case IQUERY:
    return "IQUERY";
  case STATUS:
    return "STATUS";
  case NOTIFY:
    return "NOTIFY";
  case UPDATE:
    return "UPDATE";
  default:
    return f("UNKNOWN(%d)", code);
  }
}
void Header::write_to(string &buffer) {
  buffer.append((const char *)this, sizeof(*this));
}
string Header::to_string() const {
  string r = "dns::Header {\n";
  r += "  id: " + f("0x%04hx", ntohs(id)) + "\n";
  r += "  reply: " + std::to_string(reply) + "\n";
  r += "  opcode: " + string(OperationCodeToString(opcode)) + "\n";
  r += "  authoritative: " + std::to_string(authoritative) + "\n";
  r += "  truncated: " + std::to_string(truncated) + "\n";
  r += "  recursion_desired: " + std::to_string(recursion_desired) + "\n";
  r += "  recursion_available: " + std::to_string(recursion_available) + "\n";
  r += "  response_code: " + string(ResponseCodeToString(response_code)) + "\n";
  r += "  question_count: " + std::to_string(ntohs(question_count)) + "\n";
  r += "  answer_count: " + std::to_string(ntohs(answer_count)) + "\n";
  r += "  authority_count: " + std::to_string(ntohs(authority_count)) + "\n";
  r += "  additional_count: " + std::to_string(ntohs(additional_count)) + "\n";
  r += "}";
  return r;
}
void Entry::HandleIncomingRequest(const IncomingRequest &request) const {
  visit(overloaded{
            [&](Ready &r) {
              LOG << f("#%04hx %s:%hu Answering %s (cached)", request.header.id,
                       request.client_ip.to_string().c_str(),
                       request.client_port, question.to_html().c_str());
              string err;
              AnswerRequest(request, *this, err);
              if (!err.empty()) {
                ERROR << err;
              }
            },
            [&](Pending &p) {
              for (auto &r : p.incoming_requests) {
                if (r.client_ip == request.client_ip &&
                    r.client_port == request.client_port &&
                    r.header.id == request.header.id) {
                  // Ignore duplicate request
                  return;
                }
              }
              UpdateExpiration(steady_clock::now() + kPendingTTL);
              p.incoming_requests.push_back(request);
            },
        },
        state);
}
void Message::Parse(const char *ptr, size_t len, string &err) {
  if (len < sizeof(Header)) {
    err = "DNS message buffer is too short: " + std::to_string(len) +
          " bytes. DNS header requires at least 12 bytes. Hex-escaped "
          "buffer: " +
          BytesToHex(ptr, len);
    return;
  }
  header = *(Header *)ptr;

  if (ntohs(header.question_count) != 1) {
    err = "DNS message contains more than one question. This is not supported.";
    return;
  }

  size_t offset = sizeof(Header);
  if (auto q_size = question.LoadFrom(ptr, len, offset)) {
    offset += q_size;
  } else {
    err = "Failed to load DNS question from " + BytesToHex(ptr, len);
    return;
  }

  auto LoadRecordList = [&](vector<Record> &v, uint16_t n) {
    for (int i = 0; i < n; ++i) {
      Record &r = v.emplace_back();
      if (auto r_size = r.LoadFrom(ptr, len, offset)) {
        offset += r_size;
      } else {
        err = "Failed to load a record from DNS query. Full query:\n" +
              BytesToHex(ptr, len);
        return;
      }
    }
  };

  LoadRecordList(answers, ntohs(header.answer_count));
  if (!err.empty())
    return;
  LoadRecordList(authority, ntohs(header.authority_count));
  if (!err.empty())
    return;
  LoadRecordList(additional, ntohs(header.additional_count));
  if (!err.empty())
    return;
}
string Message::to_string() const {
  string r = "dns::Message {\n";
  r += IndentString(header.to_string()) + "\n";
  r += "  " + question.to_string() + "\n";
  for (const Record &a : answers) {
    r += "  " + a.to_string() + "\n";
  }
  for (const Record &a : authority) {
    r += "  " + a.to_string() + "\n";
  }
  for (const Record &a : additional) {
    r += "  " + a.to_string() + "\n";
  }
  r += "}";
  return r;
}
void Message::ForEachRecord(function<void(const Record &)> f) const {
  for (const Record &r : answers) {
    f(r);
  }
  for (const Record &r : authority) {
    f(r);
  }
  for (const Record &r : additional) {
    f(r);
  }
}
void Entry::HandleAnswer(const Message &msg, string &err) const {
  auto *pending = get_if<Pending>(&state);
  if (pending == nullptr) {
    err = "Received an answer for a ready entry: " + question.to_string();
    return;
  }

  if (pending->outgoing_id != msg.header.id) {
    err =
        "Received an answer with an wrong ID: " + f("0x%04hx", msg.header.id) +
        " (expected: " + f("0x%04hx", pending->outgoing_id) + ")";
    return;
  }

  vector<IncomingRequest> incoming_requests =
      std::move(pending->incoming_requests);
  state.emplace<Ready>(Ready{.response_code = msg.header.response_code,
                             .answers = std::move(msg.answers),
                             .authority = std::move(msg.authority),
                             .additional = std::move(msg.additional)});

  steady_clock::time_point new_expiration =
      steady_clock::now() +
      (msg.header.response_code == ResponseCode::NAME_ERROR ? 60s : 24h);
  msg.ForEachRecord([&](const Record &r) {
    auto record_expiration = get_if<steady_clock::time_point>(&r.expiration);
    if (record_expiration != nullptr && *record_expiration < new_expiration) {
      new_expiration = *record_expiration;
    }
  });

  UpdateExpiration(new_expiration);

  LOG << f("Received %s from upstream. Caching for %s.",
           question.to_html().c_str(),
           FormatDuration(new_expiration - steady_clock::now()).c_str());

  for (auto &inc_req : incoming_requests) {
    AnswerRequest(inc_req, *this, err);
    LOG << f("#%04hx %s:%hu Answering %s (from upstream)", inc_req.header.id,
             inc_req.client_ip.to_string().c_str(), inc_req.client_port,
             msg.question.to_html().c_str());
    if (!err.empty()) {
      break;
    }
  }
}

void Stop() {
  client.StopListening();
  server.StopListening();
}

Table::Table() : webui::Table("dns", "DNS", {"Expiration", "Entry"}) {}

void Table::Update(RenderOptions &opts) {
  rows.clear();
  auto now = steady_clock::now();
  for (auto [time, entry] : expiration_queue) {
    rows.emplace_back(Row{
        .question = entry->question.to_html(),
        .orig_question = entry->question,
        .expiration = FormatDuration(time - now),
        .expiration_time = time,
    });
  }
  if (opts.sort_column) {
    sort(rows.begin(), rows.end(), [&](const Row &a, const Row &b) {
      bool result = true;
      if (opts.sort_column == 0) {
        result = a.expiration_time < b.expiration_time;
      } else if (opts.sort_column == 1) {
        result = a.question < b.question;
      }
      return opts.sort_descending ? !result : result;
    });
  }
}

int Table::Size() const { return rows.size(); }

void Table::Get(int row, int col, string &out) const {
  if (row < 0 || row >= Size()) {
    return;
  }
  switch (col) {
  case 0:
    out = rows[row].expiration;
    break;
  case 1:
    out = rows[row].question;
    break;
  }
}

std::string Table::RowID(int row) const {
  if (row < 0 || row >= rows.size()) {
    return "";
  }
  string id = "dns-";
  for (char c : rows[row].orig_question.domain_name) {
    if (isalnum(c)) {
      id += c;
    } else {
      id += '-';
    }
  }
  id += '-';
  id += TypeToString(rows[row].orig_question.type);
  return id;
}

Table table;

} // namespace dns
