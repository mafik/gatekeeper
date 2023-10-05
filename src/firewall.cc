#include "firewall.hh"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <set>
#include <sys/prctl.h>
#include <unistd.h>

#include <csignal>
#include <optional>
#include <thread>
#include <unordered_set>
#include <utility>

#include "config.hh"
#include "format.hh"
#include "log.hh"
#include "netfilter.hh"
#include "netlink.hh"
#include "nfqueue.hh"
#include "status.hh"

using namespace maf;
using namespace netfilter;
using namespace std::string_literals;

// Gatekeeper sets up a firewall that intercepts all traffic between LAN & WAN.
//
// Gatekeeper firewall is capable of in-flight packet modification and uses this
// for NAT translation. It replaces the Linux conntrack system.
//
// Netfilter rules created by Gatekeeper can be inspected by running:
//
//   sudo nft list table gatekeeper
//
// All firewall rules are cleaned up on shutdown.
namespace gatekeeper::firewall {

static constexpr bool kLogPackets = false;
static constexpr char kTableName[] = "gatekeeper";

// Equivalent to:
// oif != 3 ip saddr 10.1.0.0/16 notrack counter queue to 1337
static std::string PostroutingRule() {
  std::string base =
      "\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00"
      "\x02\x80\x08\x00\x02\x00\x00\x00\x00\x05\x08\x00\x01\x00\x00\x00\x00\x01"
      "\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00"
      "\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x0c\x00\x03\x80"
      "\x08\x00\x01\x00\x44\x33\x22\x11\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61"
      "\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01"
      "\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x0c\x08\x00"
      "\x04\x00\x00\x00\x00\x02\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00"
      "\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00"
      "\x00\x00\x0c\x00\x03\x80\x06\x00\x01\x00\x55\x66\x00\x00\x10\x00\x01\x80"
      "\x0c\x00\x01\x00\x6e\x6f\x74\x72\x61\x63\x6b\x00\x14\x00\x01\x80\x0c\x00"
      "\x01\x00\x63\x6f\x75\x6e\x74\x65\x72\x00\x04\x00\x02\x80\x24\x00\x01\x80"
      "\x0a\x00\x01\x00\x71\x75\x65\x75\x65\x00\x00\x00\x14\x00\x02\x80\x06\x00"
      "\x01\x00\x05\x39\x00\x00\x06\x00\x02\x00\x00\x01\x00\x00"s;
  *(uint32_t *)(base.data() + 76) = lan.index;
  *(uint32_t *)(base.data() + 172) = lan_network.ip.addr;
  return base;
}

// Equivalent to:
// iif != 3 ip daddr 10.0.0.8 notrack counter queue to 1337
static std::string PreroutingRule() {
  std::string base =
      "\x24\x00\x01\x80\x09\x00\x01\x00\x6d\x65\x74\x61\x00\x00\x00\x00\x14\x00"
      "\x02\x80\x08\x00\x02\x00\x00\x00\x00\x04\x08\x00\x01\x00\x00\x00\x00\x01"
      "\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00\x20\x00\x02\x80\x08\x00"
      "\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00\x00\x01\x0c\x00\x03\x80"
      "\x08\x00\x01\x00\x44\x33\x22\x11\x34\x00\x01\x80\x0c\x00\x01\x00\x70\x61"
      "\x79\x6c\x6f\x61\x64\x00\x24\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01"
      "\x08\x00\x02\x00\x00\x00\x00\x01\x08\x00\x03\x00\x00\x00\x00\x10\x08\x00"
      "\x04\x00\x00\x00\x00\x04\x2c\x00\x01\x80\x08\x00\x01\x00\x63\x6d\x70\x00"
      "\x20\x00\x02\x80\x08\x00\x01\x00\x00\x00\x00\x01\x08\x00\x02\x00\x00\x00"
      "\x00\x00\x0c\x00\x03\x80\x08\x00\x01\x00\x55\x66\x77\x88\x10\x00\x01\x80"
      "\x0c\x00\x01\x00\x6e\x6f\x74\x72\x61\x63\x6b\x00\x14\x00\x01\x80\x0c\x00"
      "\x01\x00\x63\x6f\x75\x6e\x74\x65\x72\x00\x04\x00\x02\x80\x24\x00\x01\x80"
      "\x0a\x00\x01\x00\x71\x75\x65\x75\x65\x00\x00\x00\x14\x00\x02\x80\x06\x00"
      "\x01\x00\x05\x39\x00\x00\x06\x00\x02\x00\x00\x01\x00\x00"s;
  *(uint32_t *)(base.data() + 76) = lan.index;
  *(uint32_t *)(base.data() + 172) = wan_ip.addr;
  return base;
}

struct NetfilterHook {
  NetfilterHook(Status &status) {
    Netlink netlink(NETLINK_NETFILTER, status);
    if (!status.Ok()) {
      status() += "Couldn't establish netlink to Netfilter";
      return;
    }
    constexpr auto family = Family::IPv4;
    Status ignore_errors;
    DelTable(netlink, Family::IPv4, kTableName, ignore_errors);
    NewTable(netlink, family, kTableName, status);
    if (!status.Ok()) {
      status() += "Error while creating netfilter table";
      return;
    }
    NewChain(netlink, family, kTableName, "POSTROUTING",
             std::make_pair(Hook::POST_ROUTING, -300), std::nullopt, status);
    if (!status.Ok()) {
      status() += "Error while creating POSTROUTING netfilter chain";
      return;
    }
    NewChain(netlink, family, kTableName, "PREROUTING",
             std::make_pair(Hook::PRE_ROUTING, -300), std::nullopt, status);
    if (!status.Ok()) {
      status() += "Error while creating PREROUTING netfilter chain";
      return;
    }
    NewRule(netlink, family, kTableName, "POSTROUTING", PostroutingRule(),
            status);
    if (!status.Ok()) {
      status() += "Error while creating POSTROUTING netfilter rule";
      status() +=
          "Note: the following error is known to happen when Linux lacks "
          "support for packet processing in userspace. Make sure to install & "
          "load kernel modules: nfnetlink-queue & nft-queue";
      return;
    }
    NewRule(netlink, family, kTableName, "PREROUTING", PreroutingRule(),
            status);
    if (!status.Ok()) {
      status() += "Error while creating PREROUTING netfilter rule";
      return;
    }
    // On some machines the default policy of "filter" "FORWARD" is to drop.
    // We override it with "accept".
    // Errors can be safely ignored - not all devices have this table.
    Status status_ignore;
    NewChain(netlink, Family::IPv4, "filter", "FORWARD", std::nullopt, true,
             status_ignore);
    DisableOpenWRTFirewall(netlink);
  }

  // OpenWRT ships with a firewall (called "fw4") and plenty of rules for
  // handling different types of (often malicious) traffic. We take care of all
  // of that in userspace. This function clears all of "fw4" rules so they don't
  // interfere.
  void DisableOpenWRTFirewall(Netlink &netlink) {
    Status ok_if_openwrt;
    DelTable(netlink, Family::INET, "fw4", ok_if_openwrt);
    if (ok_if_openwrt.Ok()) {
      LOG << "Disabled OpenWRT fw4 firewall. This is OK because Gatekeeper "
             "will take care of it now.";
    }
  }

  ~NetfilterHook() {
    Status status;
    Netlink netlink(NETLINK_NETFILTER, status);
    if (!status.Ok()) {
      return;
    }
    DelTable(netlink, Family::IPv4, kTableName, status);
  }
};

std::optional<NetfilterHook> hook;
std::optional<Netlink> queue;

std::thread loop;

enum class ProtocolID : uint8_t {
  ICMP = 1,
  TCP = 6,
  UDP = 17,
};

std::string ProtocolIDToString(ProtocolID proto) {
  switch (proto) {
  case ProtocolID::ICMP:
    return "ICMP";
  case ProtocolID::TCP:
    return "TCP";
  case ProtocolID::UDP:
    return "UDP";
  }
  return f("%d", (int)proto);
}

struct IP_Header {
  uint8_t version_ihl;
  uint8_t tos;
  uint16_t total_length;
  uint16_t frag_id;
  uint16_t frag_offset;
  uint8_t ttl;
  ProtocolID proto;
  uint16_t checksum;
  IP source_ip;
  IP destination_ip;

  size_t HeaderLength() const { return (version_ihl & 0xf) * 4; }

  void UpdateChecksum() {
    checksum = 0;
    uint32_t sum = 0;
    uint16_t *p = (uint16_t *)this;
    uint16_t *end = (uint16_t *)((char *)this + HeaderLength());
    for (; p < end; ++p) {
      sum += ntohs(*p);
    }
    while (sum >> 16) {
      sum = (sum & 0xffff) + (sum >> 16);
    }
    checksum = htons(~sum);
  }
};

static_assert(sizeof(IP_Header) == 20, "IP_Header should have 20 bytes");

// Base class for TCP & UDP headers
struct INET_Header {
  uint16_t source_port;
  uint16_t destination_port;
};

struct TCP_Header : INET_Header {
  uint32_t seq;
  uint32_t ack;
  uint8_t offset_reserved;
  uint8_t flags;
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent;

  size_t HeaderLength() const { return ((offset_reserved & 0xf0) >> 2); }
};

static_assert(sizeof(TCP_Header) == 20, "TCP_Header should have 20 bytes");

struct UDP_Header : INET_Header {
  uint16_t length;
  uint16_t checksum;
};

static_assert(sizeof(UDP_Header) == 8, "UDP_Header should have 8 bytes");

void UpdateLayer4Checksum(IP_Header &ip, uint16_t &checksum) {
  checksum = 0;
  uint32_t sum = 0;
  uint16_t header_len = ip.HeaderLength();
  uint16_t data_len = ntohs(ip.total_length) - header_len;
  sum += ntohs(ip.source_ip.halves[0]);
  sum += ntohs(ip.source_ip.halves[1]);
  sum += ntohs(ip.destination_ip.halves[0]);
  sum += ntohs(ip.destination_ip.halves[1]);
  sum += data_len;
  sum += (uint16_t)ip.proto;
  uint8_t *buff = (uint8_t *)&ip + header_len;
  for (int i = 0; i < (data_len / 2); i++) {
    sum += ntohs((buff[i * 2 + 1] << 8) | buff[i * 2]);
  }
  if ((data_len % 2) == 1) {
    sum += buff[data_len - 1] << 8;
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  sum = ~sum;
  checksum = htons((uint16_t)sum);
}

struct FullConeNAT {
  // Note: theoretically we could only store the last two bytes of the IP
  // because our network is /16. This might change in the future though and it's
  // not that much of a saving anyway so let's keep things simple.
  IP lan_host_ip;

  static FullConeNAT &Lookup(ProtocolID protocol, uint16_t local_port);
};

static FullConeNAT nat_table[2][65536];

FullConeNAT &FullConeNAT::Lookup(ProtocolID protocol, uint16_t local_port) {
  int protocol_index = protocol == ProtocolID::TCP ? 0 : 1;
  return nat_table[protocol_index][local_port];
}

struct SymmetricNAT {
  struct Key {
    IP remote_ip;
    uint16_t remote_port;
    uint16_t local_port;

    bool operator==(const Key &other) const {
      return remote_ip == other.remote_ip && remote_port == other.remote_port &&
             local_port == other.local_port;
    }

    size_t Hash() const { return *reinterpret_cast<const size_t *>(this); }
  } key;
  IP local_ip;
  std::chrono::steady_clock::time_point last_used;

  struct OrderByLastUsed {
    using is_transparent = std::true_type;

    bool operator()(const SymmetricNAT *a, const SymmetricNAT *b) const {
      return a->last_used < b->last_used;
    }

    bool operator()(const SymmetricNAT *a,
                    const std::chrono::steady_clock::time_point b) const {
      return a->last_used < b;
    }

    bool operator()(const std::chrono::steady_clock::time_point a,
                    const SymmetricNAT *b) const {
      return a < b->last_used;
    }
  };

  struct HashByRemote {
    using is_transparent = std::true_type;

    size_t operator()(const SymmetricNAT *n) const { return n->key.Hash(); }
    size_t operator()(const Key &key) const { return key.Hash(); }
  };

  struct EqualByRemote {
    using is_transparent = std::true_type;

    bool operator()(const SymmetricNAT *a, const SymmetricNAT *b) const {
      return a->key == b->key;
    }

    bool operator()(const Key &a, const SymmetricNAT *b) const {
      return a == b->key;
    }
  };

  static std::multiset<SymmetricNAT *, OrderByLastUsed> expiration_queue;
  static std::unordered_set<SymmetricNAT *, HashByRemote, EqualByRemote> table;

  void BumpExpiration() {
    // First remove self from the expiration queue
    auto [begin, end] = expiration_queue.equal_range(last_used);
    for (auto it = begin; it != end; ++it) {
      SymmetricNAT *exp = *it;
      if (exp == this) {
        expiration_queue.erase(it);
        break;
      }
    }
    // Then update the last_used time and re-insert
    last_used = std::chrono::steady_clock::now();
    expiration_queue.insert(this);
  }

  static void ExpireOldEntries() {
    auto cutoff = std::chrono::steady_clock::now() - std::chrono::minutes(30);
    while (!expiration_queue.empty() &&
           (*expiration_queue.begin())->last_used < cutoff) {
      SymmetricNAT *entry = *expiration_queue.begin();
      expiration_queue.erase(expiration_queue.begin());
      table.erase(entry);
      delete entry;
    }
  }
};

std::multiset<SymmetricNAT *, SymmetricNAT::OrderByLastUsed>
    SymmetricNAT::expiration_queue;
std::unordered_set<SymmetricNAT *, SymmetricNAT::HashByRemote,
                   SymmetricNAT::EqualByRemote>
    SymmetricNAT::table;

void OnReceive(nfgenmsg &msg, std::span<Netlink::Attr *> attrs) {
  if (attrs[NFQA_PACKET_HDR] == nullptr) {
    ERROR << "NFQA_PACKET_HDR is missing";
    return;
  }
  nfqnl_msg_packet_hdr &phdr =
      attrs[NFQA_PACKET_HDR]->As<nfqnl_msg_packet_hdr>();

  netfilter::Verdict verdict(phdr.packet_id, true);

  if (attrs[NFQA_PAYLOAD] == nullptr) {
    ERROR << "NFQA_PAYLOAD is missing";
    return;
  }
  std::string_view payload = attrs[NFQA_PAYLOAD]->View();
  IP_Header &ip = attrs[NFQA_PAYLOAD]->As<IP_Header>();

  bool from_lan = lan_network.Contains(ip.source_ip);
  bool to_lan = lan_network.Contains(ip.destination_ip);
  bool to_internet = !to_lan && (ip.destination_ip != IP(255, 255, 255, 255));
  bool has_ports = ip.proto == ProtocolID::TCP || ip.proto == ProtocolID::UDP;
  bool packet_modified = false;

  INET_Header &inet = *(INET_Header *)(payload.data() + ip.HeaderLength());
  TCP_Header &tcp = *(TCP_Header *)(&inet);
  UDP_Header &udp = *(UDP_Header *)(&inet);

  if constexpr (kLogPackets) {
    std::string protocol_string = ProtocolIDToString(ip.proto);
    if (ip.proto == ProtocolID::TCP) {
      protocol_string += f(" %5d -> %-5d", ntohs(tcp.source_port),
                           ntohs(tcp.destination_port));
    } else if (ip.proto == ProtocolID::UDP) {
      protocol_string += f(" %5d -> %-5d", ntohs(udp.source_port),
                           ntohs(udp.destination_port));
    }
    uint32_t packet_id = ntohl(phdr.packet_id);
    LOG << f("#%04x ", packet_id)
        << f("%15s", ip.source_ip.LoggableString().c_str()) << " => "
        << f("%-15s", ip.destination_ip.LoggableString().c_str()) << " ("
        << protocol_string << "): " << f("%4d", payload.size()) << " B";
  }

  auto &checksum = ip.proto == ProtocolID::TCP ? tcp.checksum : udp.checksum;
  int socket_type = ip.proto == ProtocolID::TCP ? SOCK_STREAM : SOCK_DGRAM;

  SymmetricNAT::ExpireOldEntries();

  if (ip.destination_ip == wan_ip && !from_lan && has_ports) {
    // Packet coming to our WAN IP from outside of LAN.
    // We may need to modify the destination (NAT demangling).

    // Attempt to find a matching entry in the Symmetric NAT table.
    auto it = SymmetricNAT::table.find<SymmetricNAT::Key>(
        {ip.source_ip, inet.source_port, inet.destination_port});
    if (it != SymmetricNAT::table.end()) {
      // Found a matching entry. Update the last_used time.
      (*it)->BumpExpiration();
      // Mangle the destination IP to point at the LAN IP
      ip.destination_ip = (*it)->local_ip;
      packet_modified = true;
    } else {
      // If no Symmetric NAT entry exists, try the Full Cone NAT table.
      FullConeNAT &fullcone =
          FullConeNAT::Lookup(ip.proto, inet.destination_port);
      if (fullcone.lan_host_ip.addr != 0) {
        ip.destination_ip = fullcone.lan_host_ip;
        packet_modified = true;
      }
    }
  } else if (from_lan && to_internet && ip.source_ip != lan_ip && has_ports) {
    // Packet coming from LAN into the Internet.
    // We have to modify the source (NAT mangling).

    // Record the original source IP in the Full Cone NAT table.
    // New packets from unknown sources will be sent to this LAN IP.
    FullConeNAT &fullcone = FullConeNAT::Lookup(ip.proto, inet.source_port);
    fullcone.lan_host_ip = ip.source_ip;

    // Record the original source IP in the Symmetric NAT table.
    // New packets from this destination will be sent back to this LAN IP.
    auto it = SymmetricNAT::table.find<SymmetricNAT::Key>(
        {ip.destination_ip, inet.destination_port, inet.source_port});
    if (it == SymmetricNAT::table.end()) {
      SymmetricNAT *e = new SymmetricNAT{
          .key = {ip.destination_ip, inet.destination_port, inet.source_port},
          .local_ip = ip.source_ip,
          .last_used = std::chrono::steady_clock::now(),
      };
      SymmetricNAT::table.insert(e);
      SymmetricNAT::expiration_queue.insert(e);
    } else {
      (*it)->BumpExpiration();
    }
    // Mangle the source IP to point back at our WAN IP
    ip.source_ip = wan_ip;
    packet_modified = true;
  }

  Status status;
  if (packet_modified) {
    ip.UpdateChecksum();
    UpdateLayer4Checksum(ip, checksum);
    queue->SendWithAttr(verdict, *attrs[NFQA_PAYLOAD], status);
  } else {
    queue->Send(verdict, status);
  }
  if (!status.Ok()) {
    status() += "Couldn't send verdict";
    ERROR << status;
  }
}

std::atomic_int loop_tid = 0;

bool stop = false;

static void sig_handler(int signum) { stop = true; }

void Loop() {
  prctl(PR_SET_NAME, "Firewall loop", 0, 0, 0);
  loop_tid = gettid();
  while (!stop) {
    Status status;
    queue->ReceiveT<nfgenmsg>(NFNL_SUBSYS_QUEUE << 8 | NFQNL_MSG_PACKET,
                              OnReceive, status);
    if (!stop && !status.Ok()) {
      status() += "Firewall failed to receive message from kernel";
      ERROR << status;
    }
  }
}

void Start(Status &status) {
  hook.emplace(status);
  if (!status.Ok()) {
    hook.reset();
    return;
  }

  queue.emplace(NETLINK_NETFILTER, status);
  if (!status.Ok()) {
    queue.reset();
    hook.reset();
    return;
  }

  Bind bind;
  queue->Send(bind, status);

  CopyPacket copy_packet;
  queue->Send(copy_packet, status);

  // Use SIGUSR1 to stop the firewall loop.
  //
  // This may seem strange but it's the best way to interrupt the blocked `recv`
  // call.
  //
  // Signal is established using sigaction to avoid SA_RESTART flag, and make
  // the `recv` call return EINTR.
  //
  // One alternative might be to use a pipe and `select` to wait for either data
  // from the firewall queue or a stop command.
  struct sigaction sa = {};
  sa.sa_handler = sig_handler;
  sigaction(SIGUSR1, &sa, nullptr);

  loop = std::thread(Loop);
}

void Stop() {
  tgkill(getpid(), loop_tid, SIGUSR1);
  loop.join();
  queue.reset();
  hook.reset();
}

} // namespace gatekeeper::firewall