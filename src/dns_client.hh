#pragma once

#include "dns_utils.hh"
#include "expirable.hh"
#include "fn.hh"
#include "ip.hh"
#include "status.hh"
#include "str.hh"
#include <chrono>
#include <unordered_set>

namespace maf::dns {

// TODO: try to merge this with CachedEntry
struct Message;

// Abstract base class for DNS lookups.
struct LookupBase {
  bool in_progress;
  LookupBase();
  virtual ~LookupBase();

  // Call this at the end of the constructor. This will start the lookup.
  // Eventually either `OnAnswer` or `OnExpired` will be called.
  void Start(Str domain, U16 type);

  // Called if the DNS client cannot be started.
  virtual void OnStartupFailure(Status &) = 0;

  // Called when we receive a DNS response. Receives the full DNS response.
  virtual void OnAnswer(const Message &) = 0;

  // Called when the lookup expires.
  virtual void OnExpired() = 0;
};

// Main class for performing DNS lookups.
struct LookupIPv4 : LookupBase {
  Fn<void(IP ip)> on_success;
  Fn<void()> on_error;

  void Start(Str domain);

  void OnStartupFailure(Status &) override;
  void OnAnswer(const Message &) override;
  void OnExpired() override;
};

const Str *LocalReverseLookup(IP ip);
void Override(const Str &domain, IP ip);

void StartClient(Status &);
void StopClient();

struct Entry : Expirable {
  Question question;
  Entry(std::chrono::steady_clock::duration ttl, const Question &question)
      : Expirable(ttl), question(question) {
    cache.insert(this);
  }
  Entry(const Question &question) : Expirable(), question(question) {
    cache.insert(this);
  }
  virtual ~Entry() { cache.erase(cache.find(this)); }

  struct QuestionHash {
    using is_transparent = std::true_type;

    size_t operator()(const Question &q) const {
      return std::hash<Str>()(q.domain_name) ^ std::hash<Type>()(q.type) ^
             std::hash<Class>()(q.class_);
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

  static std::unordered_set<Entry *, QuestionHash, QuestionEqual> cache;
};

} // namespace maf::dns