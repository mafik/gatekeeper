#include "dns_client.hh"

#include <chrono>
#include <optional>
#include <unordered_set>

#include "big_endian.hh"
#include "dns_utils.hh"
#include "epoll_udp.hh"
#include "etc.hh"
#include "expirable.hh"
#include "format.hh"
#include "log.hh"
#include "optional.hh"
#include "random.hh"

namespace maf::dns {

using namespace std;

static int server_i = 0;

// Use privileged port for DNS client - to reduce the chance of NAT collision.
static constexpr U16 kClientPort = 22339;

Big<U16> AllocateRequestId() {
  // Randomize initial request ID
  static Big<U16> request_id = random<U16>();
  // Subsequent request IDs are incremented by 1
  request_id.Set(request_id + 1);
  return request_id;
}

unordered_set<Entry *, Entry::QuestionHash, Entry::QuestionEqual> Entry::cache;

struct HashByData {
  using is_transparent = std::true_type;
  size_t operator()(const Record *r) const { return hash<Span<>>()(r->data); }
  // Allow querying using IP address (for A records).
  size_t operator()(const IP &ip) const {
    return hash<Span<>>()(SpanOfRef(ip));
  }
};

struct EqualData {
  using is_transparent = std::true_type;
  bool operator()(const Record *a, const Record *b) const {
    return a->data == b->data;
  }
  bool operator()(const Record *a, const IP &b) const {
    return Span<>(a->data) == SpanOfRef(b);
  }
  bool operator()(const IP &a, const Record *b) const {
    return SpanOfRef(a) == Span<>(b->data);
  }
};

unordered_multiset<const Record *, HashByData, EqualData> cache_reverse;

struct PendingEntry : Entry {
  Big<U16> id;
  Vec<LookupBase *> in_progress;
  PendingEntry(Question question, Big<U16> id, LookupBase *lookup);
  ~PendingEntry() override {
    for (auto *lookup : in_progress) {
      lookup->in_progress = false;
      StopClient();
      lookup->OnExpired();
    }
  }
};

struct CachedEntry : Entry {
  CachedEntry(Message &msg)
      : Entry(msg.questions.front()), response_code(msg.header.response_code),
        answers(msg.answers), authority(msg.authority),
        additional(msg.additional) {

    Optional<chrono::steady_clock::time_point> new_expiration = nullopt;
    if (msg.header.response_code != ResponseCode::NO_ERROR) {
      new_expiration = chrono::steady_clock::now() + 60s;
    } else {
      msg.ForEachRecord([&](const Record &r) {
        auto record_expiration = r.expiration;
        if (record_expiration.has_value()) {
          if (new_expiration.has_value()) {
            if (*record_expiration < *new_expiration) {
              new_expiration = record_expiration;
            }
          } else {
            new_expiration = record_expiration;
          }
        }
      });
    }
    if (new_expiration.has_value()) {
      UpdateExpiration(*new_expiration);
    }

    for (auto &answer : answers) {
      if (answer.type == Type::A) {
        cache_reverse.insert(&answer);
      }
    }
  }
  ~CachedEntry() override {
    for (const auto &r : answers) {
      if (r.type == Type::A) {
        cache_reverse.erase(&r);
      }
    }
  }
  ResponseCode response_code;
  Vec<Record> answers;
  Vec<Record> authority;
  Vec<Record> additional;

  Str ToStr() const {
    Str r = "CachedEntry(" + Str(dns::ToStr(response_code));
    for (const Record &a : answers) {
      r += "  " + a.ToStr();
    }
    for (const Record &a : authority) {
      r += "  " + a.ToStr();
    }
    for (const Record &a : additional) {
      r += "  " + a.ToStr();
    }
    r += ")";
    return r;
  }
  Str to_html() const {
    string r = "<code>" + string(dns::ToStr(response_code)) + "</code>";
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
};

static void CancelLookup(LookupBase *lookup) {
  if (not lookup->in_progress) {
    return;
  }
  lookup->in_progress = false;
  StopClient();
  // Remove this from the pending lookups.
  for (Entry *e : Entry::cache) {
    PendingEntry *pending = dynamic_cast<PendingEntry *>(e);
    if (pending == nullptr) {
      continue;
    }
    for (int i = 0; i < pending->in_progress.size(); i++) {
      if (pending->in_progress[i] == lookup) {
        pending->in_progress.erase(pending->in_progress.begin() + i);
        return;
      }
    }
  }
}

LookupBase::LookupBase() : in_progress(false) {}

LookupBase::~LookupBase() { CancelLookup(this); }

void LookupIPv4::Start(Str domain) { LookupBase::Start(domain, (U16)Type::A); }

void LookupIPv4::OnAnswer(const Message &msg) {
  for (auto &answer : msg.answers) {
    if (answer.type != Type::A) {
      continue;
    }
    if (answer.data.size() != sizeof(IP)) {
      continue;
    }
    IP ip;
    memcpy(&ip.addr, answer.data.data(), sizeof(ip.addr));
    on_success(ip);
    return;
  }
  on_error();
}

void LookupIPv4::OnStartupFailure(Status &status) { on_error(); }

void LookupIPv4::OnExpired() { on_error(); }

struct Client : epoll::UDPListener {
  U32 refs = 0;

  void Listen(Status &status) {
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd == -1) {
      AppendErrorMessage(status) += "socket";
      return;
    }

    int flag = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, (char *)&flag,
                   sizeof(flag)) < 0) {
      AppendErrorMessage(status) += "setsockopt: SO_REUSEADDR";
      StopListening();
      return;
    }

    fd.Bind(INADDR_ANY, kClientPort, status);
    if (!OK(status)) {
      StopListening();
      return;
    }

    epoll::Add(this, status);
  }

  void StopListening() {
    Status ignored;
    epoll::Del(this, ignored);
    shutdown(fd, SHUT_RDWR);
    fd.Close();
  }

  void HandleRequest(StrView buf, IP source_ip, U16 source_port) override {
    if (find(etc::resolv.begin(), etc::resolv.end(), source_ip) ==
        etc::resolv.end()) {
      Str dns_servers = "";
      for (const auto &server : etc::resolv) {
        if (!dns_servers.empty()) {
          dns_servers += " / ";
        }
        dns_servers += ToStr(server);
      }
      LOG << "DNS client received a packet from an unexpected source: "
          << ToStr(source_ip) << " (expected: " << dns_servers << ")";
      return;
    }
    if (source_port != kServerPort) {
      LOG << "DNS client received a packet from an unexpected source port: "
          << source_port << " (expected port " << kServerPort << ")";
      return;
    }
    Message msg;
    Str err;
    msg.Parse(buf.data(), buf.size(), err);
    if (!err.empty()) {
      ERROR << "DNS client couldn't parse response. " << err;
      return;
    }

    if (msg.header.opcode != Header::OperationCode::QUERY) {
      LOG << "DNS client received a packet with an unsupported opcode: "
          << ToStr(msg.header.opcode) << ". Full query: " << msg.header.ToStr();
      return;
    }

    if (!msg.header.reply) {
      LOG << "DNS client received a packet that is not a reply: "
          << msg.header.ToStr();
      return;
    }

    if (msg.questions.size() != 1) {
      LOG << "DNS client expected a packet with one question. Received: "
          << msg.ToStr();
      return;
    }

    auto entry_it = Entry::cache.find(msg.questions.front());
    if (entry_it == Entry::cache.end()) {
      LOG << "DNS client received a reply to a question that it didn't ask: "
          << msg.questions.front().ToStr();
      return;
    }
    Entry *entry = *entry_it;
    PendingEntry *pending = dynamic_cast<PendingEntry *>(entry);
    if (pending == nullptr) {
      // This is a reply to a question that we asked earlier, but we already
      // received a reply to it. This is not an error.
      return;
    }

    if (pending->id != msg.header.id) {
      err = "Received an answer with an wrong ID: " +
            f("0x%04hx", msg.header.id) +
            " (expected: " + f("0x%04hx", pending->id) + ")";
      return;
    }
    for (auto *lookup : pending->in_progress) {
      lookup->in_progress = false;
      StopClient();
      lookup->OnAnswer(msg);
    }
    pending->in_progress.clear();
    // Destructors remove the entry from the caches & expiration queue.
    delete pending;
    // Constructors add the entry to the caches & expiration queue.
    new CachedEntry(msg);
  }

  void NotifyRead(Status &epoll_status) override {
    Expirable::Expire();
    UDPListener::NotifyRead(epoll_status);
  }

  const char *Name() const override { return "dns::Client"; }
};

Client client;

void LookupBase::Start(Str domain, U16 type) {
  CancelLookup(this);
  Question question{.domain_name = domain, .type = (Type)type};
  auto entry_it = Entry::cache.find(question);
  if (entry_it == Entry::cache.end()) {
    // We don't have anything in the cache.
    // Send a new request to the upstream DNS server.

    Status status;
    StartClient(status);
    if (!OK(status)) {
      AppendErrorMessage(status) += "Failed to start DNS client";
      OnStartupFailure(status);
      return;
    }
    in_progress = true;

    Big<U16> id = AllocateRequestId();
    new PendingEntry(question, id, this);
  } else if (PendingEntry *pending = dynamic_cast<PendingEntry *>(*entry_it)) {
    // We already have a pending request for this domain.
    // Add this to the waitlist.

    Status status;
    StartClient(status);
    if (!OK(status)) {
      AppendErrorMessage(status) += "Failed to start DNS client";
      OnStartupFailure(status);
      return;
    }
    in_progress = true;

    pending->in_progress.push_back(this);
  } else if (CachedEntry *cached = dynamic_cast<CachedEntry *>(*entry_it)) {
    // We already have a cached entry for this domain.
    // Call OnAnswer immediately.
    in_progress = false;
    Message msg = {.header =
                       {
                           .id = 0,
                           .recursion_desired = true,
                           .truncated = false,
                           .authoritative = true,
                           .opcode = Header::OperationCode::QUERY,
                           .reply = true,
                           .response_code = cached->response_code,
                           .recursion_available = true,
                           .question_count = 1,
                           .answer_count = cached->answers.size(),
                           .authority_count = cached->authority.size(),
                           .additional_count = cached->additional.size(),
                       },
                   .questions = {question},
                   .answers = cached->answers,
                   .authority = cached->authority,
                   .additional = cached->additional};
    OnAnswer(msg);
  }
}

PendingEntry::PendingEntry(Question question, Big<U16> id, LookupBase *lookup)
    : Entry(kPendingTTL, question), id(id), in_progress({lookup}) {
  string buffer;
  Header{.id = id, .recursion_desired = true, .question_count = 1}.write_to(
      buffer);
  question.write_to(buffer);
  IP upstream_ip =
      etc::resolv[(++server_i) % etc::resolv.size()]; // Round-robin
  Str err;
  client.fd.SendTo(upstream_ip, kServerPort, buffer, err);
}

void Override(const Str &domain, IP ip) {
  // Don't inject if we already have an entry for this domain.
  if (Entry::cache.find(Question{.domain_name = domain}) !=
      Entry::cache.end()) {
    return;
  }
  Str encoded_domain = EncodeDomainName(domain);
  Message dummy_msg = {
      .header = {.id = 0,
                 .recursion_desired = true,
                 .truncated = false,
                 .authoritative = true,
                 .opcode = Header::OperationCode::QUERY,
                 .reply = true,
                 .response_code = ResponseCode::NO_ERROR,
                 .recursion_available = true,
                 .question_count = 1,
                 .answer_count = 1},
      .questions = {Question{.domain_name = domain}},
      .answers = {Record{Question{.domain_name = domain},
                         std::chrono::steady_clock::time_point::max(),
                         (U16)sizeof(ip.addr),
                         string((char *)&ip.addr, sizeof(ip.addr))}}};
  new CachedEntry(dummy_msg);
}

void StartClient(Status &status) {
  client.refs += 1;
  if (client.refs == 1) {
    client.Listen(status);
    if (!OK(status)) {
      client.refs -= 1;
      AppendErrorMessage(status) += "Failed to start DNS client";
      return;
    }
  }
}

void StopClient() {
  client.refs -= 1;
  if (client.refs == 0) {
    client.StopListening();
  }
}

const Str *LocalReverseLookup(IP ip) {
  if (auto it = cache_reverse.find(ip); it != cache_reverse.end()) {
    return &(*it)->domain_name;
  }
  return nullptr;
}

} // namespace maf::dns