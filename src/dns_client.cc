#include "dns_client.hh"

#include <chrono>
#include <optional>
#include <unordered_set>

#include "chrono.hh"
#include "config.hh"
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
static constexpr U16 kClientPort = 338;

U16 AllocateRequestId() {
  // Randomize initial request ID
  static U16 request_id = random<uint16_t>();
  // Subsequent request IDs are incremented by 1
  return request_id = htons(ntohs(request_id) + 1);
}

struct Entry {
  Question question;
  Entry(const Question &question) : question(question) { cache.insert(this); }
  virtual ~Entry() { cache.erase(cache.find(this)); }

  struct QuestionHash {
    using is_transparent = std::true_type;

    size_t operator()(const Question &q) const {
      return hash<string>()(q.domain_name) ^ hash<Type>()(q.type) ^
             hash<Class>()(q.class_);
    }
    size_t operator()(const Entry *e) const { return (*this)(e->question); }
  };

  struct QuestionEqual {
    using is_transparent = std::true_type;

    bool operator()(const Entry *a, const Entry *b) const {
      return a->question == b->question;
    }
    bool operator()(const Question &a, const Entry *b) const {
      return a == b->question;
    }
  };

  static unordered_set<Entry *, QuestionHash, QuestionEqual> cache;
};

unordered_set<Entry *, Entry::QuestionHash, Entry::QuestionEqual> Entry::cache;

struct HashByData {
  using is_transparent = std::true_type;
  size_t operator()(const Record *r) const { return hash<StrView>()(r->data); }
  // Allow querying using IP address (for A records).
  size_t operator()(const IP &ip) const { return hash<StrView>()(ip); }
};

struct EqualData {
  using is_transparent = std::true_type;
  bool operator()(const Record *a, const Record *b) const {
    return a->data == b->data;
  }
  bool operator()(const Record *a, const IP &b) const {
    return StrView(a->data) == StrView(b);
  }
  bool operator()(const IP &a, const Record *b) const {
    return StrView(a) == StrView(b->data);
  }
};

unordered_multiset<const Record *, HashByData, EqualData> cache_reverse;

struct PendingEntry : Expirable, Entry {
  U16 id;
  Vec<LookupBase *> in_progress;
  PendingEntry(Question question, U16 id, LookupBase *lookup);
  ~PendingEntry() override {
    for (auto *lookup : in_progress) {
      lookup->in_progress = false;
      lookup->OnExpired();
    }
  }
};

struct CachedEntry : Expirable, Entry {
  CachedEntry(Message &msg)
      : Entry(msg.questions.front()), response_code(msg.header.response_code),
        answers(msg.answers), authority(msg.authority),
        additional(msg.additional) {

    Optional<chrono::steady_clock::time_point> new_expiration = nullopt;
    if (msg.header.response_code == ResponseCode::NAME_ERROR) {
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

  Str to_string() const {
    string r = "CachedEntry(" + string(ResponseCodeToString(response_code));
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
  Str to_html() const {
    string r =
        "<code>" + string(ResponseCodeToString(response_code)) + "</code>";
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

LookupBase::LookupBase() : in_progress(false) {}

static void CancelLookup(LookupBase *lookup) {
  if (not lookup->in_progress) {
    return;
  }
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

LookupBase::~LookupBase() { CancelLookup(this); }

void LookupBase::Start(Str domain, U16 type) {
  CancelLookup(this);
  Question question{.domain_name = domain, .type = (Type)type};
  auto entry_it = Entry::cache.find(question);
  if (entry_it == Entry::cache.end()) {
    // We don't have anything in the cache.
    // Send a new request to the upstream DNS server.
    in_progress = true;
    U16 id = AllocateRequestId();
    new PendingEntry(question, id, this);
  } else if (PendingEntry *pending = dynamic_cast<PendingEntry *>(*entry_it)) {
    // We already have a pending request for this domain.
    // Add this to the waitlist.
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
                           .opcode = Header::QUERY,
                           .reply = true,
                           .response_code = cached->response_code,
                           .recursion_available = true,
                           .question_count = htons(1),
                           .answer_count = htons(cached->answers.size()),
                           .authority_count = htons(cached->authority.size()),
                           .additional_count = htons(cached->additional.size()),
                       },
                   .questions = {question},
                   .answers = cached->answers,
                   .authority = cached->authority,
                   .additional = cached->additional};
    OnAnswer(msg);
  }
}

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

void LookupIPv4::OnExpired() { on_error(); }

struct Client : UDPListener {

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
    close(fd);
  }

  void HandleRequest(StrView buf, IP source_ip, uint16_t source_port) override {
    if (find(etc::resolv.begin(), etc::resolv.end(), source_ip) ==
        etc::resolv.end()) {
      Str dns_servers = "";
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
    Str err;
    msg.Parse(buf.data(), buf.size(), err);
    if (!err.empty()) {
      ERROR << "DNS client couldn't parse response. " << err;
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

    if (msg.questions.size() != 1) {
      LOG << "DNS client expected a packet with one question. Received: "
          << msg.to_string();
      return;
    }

    auto entry_it = Entry::cache.find(msg.questions.front());
    if (entry_it == Entry::cache.end()) {
      LOG << "DNS client received a reply to a question that it didn't ask: "
          << msg.questions.front().to_string();
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

PendingEntry::PendingEntry(Question question, U16 id, LookupBase *lookup)
    : Expirable(kPendingTTL), Entry(question), id(id), in_progress({lookup}) {
  string buffer;
  Header{.id = id, .recursion_desired = true, .question_count = htons(1)}
      .write_to(buffer);
  question.write_to(buffer);
  IP upstream_ip =
      etc::resolv[(++server_i) % etc::resolv.size()]; // Round-robin
  Str err;
  client.fd.SendTo(upstream_ip, kServerPort, buffer, err);
}

void InjectAuthoritativeEntry(const Str &domain, IP ip) {
  Str encoded_domain = EncodeDomainName(domain);
  Message dummy_msg = {
      .header = {.id = 0,
                 .recursion_desired = true,
                 .truncated = false,
                 .authoritative = true,
                 .opcode = Header::QUERY,
                 .reply = true,
                 .response_code = ResponseCode::NO_ERROR,
                 .recursion_available = true,
                 .question_count = htons(1),
                 .answer_count = htons(1)},
      .questions = {Question{.domain_name = domain}},
      .answers = {Record{Question{.domain_name = domain}, nullopt,
                         (uint16_t)sizeof(ip.addr),
                         string((char *)&ip.addr, sizeof(ip.addr))}}};
  new CachedEntry(dummy_msg);
}

void StartClient(Status &status) {

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
}

void StopClient() { client.StopListening(); }

const Str *LocalReverseLookup(IP ip) {
  if (auto it = cache_reverse.find(ip); it != cache_reverse.end()) {
    return &(*it)->domain_name;
  }
  return nullptr;
}

Table::Table() : webui::Table("dns", "DNS", {"Expiration", "Entry"}) {}

void Table::Update(RenderOptions &opts) {
  rows.clear();
  auto now = chrono::steady_clock::now();
  for (auto *entry : Entry::cache) {
    CachedEntry *cached = dynamic_cast<CachedEntry *>(entry);
    if (cached == nullptr) {
      continue;
    }
    Optional<chrono::steady_clock::duration> expiration =
        cached->expiration.transform(
            [&](auto expiration) { return expiration - now; });
    rows.emplace_back(Row{
        .question = entry->question.to_html(),
        .domain = entry->question.domain_name,
        .type = (U16)entry->question.type,
        .expiration = FormatDuration(expiration),
        .expiration_time = cached->expiration,
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
  for (char c : rows[row].domain) {
    if (isalnum(c)) {
      id += c;
    } else {
      id += '-';
    }
  }
  id += '-';
  id += TypeToString((Type)rows[row].type);
  return id;
}

Table table;

} // namespace maf::dns