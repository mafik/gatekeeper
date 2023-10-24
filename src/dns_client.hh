#pragma once

#include "fn.hh"
#include "ip.hh"
#include "optional.hh"
#include "status.hh"
#include "str.hh"
#include "webui.hh"

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

  void OnAnswer(const Message &) override;
  void OnExpired() override;
};

const Str *LocalReverseLookup(IP ip);

void StartClient(Status &);
void StopClient();

struct Table : webui::Table {
  struct Row {
    Str question;
    Str domain;
    U16 type;
    Str expiration;
    Optional<std::chrono::steady_clock::time_point> expiration_time;
  };
  std::vector<Row> rows;
  Table();
  void Update(RenderOptions &) override;
  int Size() const override;
  void Get(int row, int col, Str &out) const override;
  Str RowID(int row) const override;
};

extern Table table;

} // namespace maf::dns