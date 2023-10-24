#pragma once

#include <chrono>
#include <unordered_set>

#include "epoll_udp.hh"
#include "expirable.hh"
#include "optional.hh"
#include "str.hh"
#include "webui.hh"

namespace dhcp {

using namespace maf;
using namespace std;

struct Server : UDPListener {

  struct Entry : Expirable {
    IP ip;
    MAC mac;
    Str hostname;
    Optional<chrono::steady_clock::time_point> last_activity;

    // Create a non-expiring entry.
    //
    // Entry will be recorded in the lookup tables of the DHCP server.
    Entry(Server &, IP, MAC, Str hostname);

    // Create an expiring entry.
    //
    // Entry will be recorded in the lookup tables of the DHCP server.
    Entry(Server &, IP, MAC, Str hostname, chrono::steady_clock::duration ttl);

    // Automatically removes `this` from the lookup tables of the DHCP server.
    ~Entry();
  };

  struct HashByIP {
    using is_transparent = std::true_type;
    size_t operator()(const Entry *e) const { return hash<IP>()(e->ip); }
    size_t operator()(const IP &ip) const { return hash<IP>()(ip); }
  };

  struct EqualIP {
    using is_transparent = std::true_type;
    bool operator()(const Entry *a, const Entry *b) const {
      return a->ip == b->ip;
    }
    bool operator()(const Entry *a, const IP &b) const { return a->ip == b; }
    bool operator()(const IP &a, const Entry *b) const { return a == b->ip; }
  };

  unordered_set<Entry *, HashByIP, EqualIP> entries_by_ip;

  struct HashByMAC {
    using is_transparent = std::true_type;
    size_t operator()(const Entry *e) const { return hash<MAC>()(e->mac); }
    size_t operator()(const MAC &mac) const { return hash<MAC>()(mac); }
  };

  struct EqualMAC {
    using is_transparent = std::true_type;
    bool operator()(const Entry *a, const Entry *b) const {
      return a->mac == b->mac;
    }
    bool operator()(const Entry *a, const MAC &b) const { return a->mac == b; }
    bool operator()(const MAC &a, const Entry *b) const { return a == b->mac; }
  };

  unordered_set<Entry *, HashByMAC, EqualMAC> entries_by_mac;

  void Init();

  // Start listening.
  //
  // To actually accept new connections, make sure to Poll the `epoll`
  // instance after listening.
  void Listen(Status &);

  // Stop listening.
  void StopListening();

  void HandleRequest(StrView buf, IP source_ip, U16 port) override;

  const char *Name() const override;
};

extern Server server;

struct Table : webui::Table {
  Table();
  int Size() const override;
  void Get(int row, int col, Str &out) const override;
  Str RowID(int row) const override;
};

extern Table table;

} // namespace dhcp
