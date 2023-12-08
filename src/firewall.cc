#include "firewall.hh"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <csignal>
#include <optional>
#include <thread>
#include <unordered_set>
#include <utility>

#include "config.hh"
#include "epoll.hh"
#include "expirable.hh"
#include "format.hh"
#include "log.hh"
#include "netfilter.hh"
#include "netlink.hh"
#include "nfqueue.hh"
#include "status.hh"
#include "traffic_log.hh"

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

Str ToStr(ProtocolID proto) {
  switch (proto) {
  case ProtocolID::ICMP:
    return "ICMP";
  case ProtocolID::TCP:
    return "TCP";
  case ProtocolID::UDP:
    return "UDP";
  }
  return f("ProtocolID(%d)", (int)proto);
}

struct IP_Header {
  U8 version_ihl;
  U8 tos;
  Big<U16> total_length;
  U16 frag_id;
  U16 frag_offset;
  U8 ttl;
  ProtocolID proto;
  U16 checksum;
  IP source_ip;
  IP destination_ip;

  Size HeaderLength() const { return (version_ihl & 0xf) * 4; }

  void UpdateChecksum() {
    checksum = 0;
    U32 sum = 0;
    U16 *p = (U16 *)this;
    U16 *end = (U16 *)((char *)this + HeaderLength());
    for (; p < end; ++p) {
      sum += Big(*p).big_endian;
    }
    while (sum >> 16) {
      sum = (sum & 0xffff) + (sum >> 16);
    }
    checksum = Big<U16>(~sum).big_endian;
  }
};

static_assert(sizeof(IP_Header) == 20, "IP_Header should have 20 bytes");

// Base class for TCP & UDP headers
struct INET_Header {
  Big<U16> source_port;
  Big<U16> destination_port;
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

void UpdateLayer4Checksum(IP_Header &ip, U16 &checksum) {
  checksum = 0;
  U32 sum = 0;
  U16 header_len = ip.HeaderLength();
  U16 data_len = ip.total_length - header_len;
  sum += ip.source_ip.halves[0];
  sum += ip.source_ip.halves[1];
  sum += ip.destination_ip.halves[0];
  sum += ip.destination_ip.halves[1];
  sum += data_len;
  sum += (U16)ip.proto;
  U8 *buff = (U8 *)&ip + header_len;
  for (int i = 0; i < (data_len / 2); i++) {
    sum += Big<U16>((buff[i * 2 + 1] << 8) | buff[i * 2]).big_endian;
  }
  if ((data_len % 2) == 1) {
    sum += buff[data_len - 1] << 8;
  }
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  sum = ~sum;
  checksum = Big<U16>(sum).big_endian;
}

struct FullConeNAT {
  // Note: theoretically we could only store the last two bytes of the IP
  // because our network is /16. This might change in the future though and it's
  // not that much of a saving anyway so let's keep things simple.
  IP lan_host_ip;

  static FullConeNAT &Lookup(ProtocolID protocol, U16 local_port);
};

static FullConeNAT nat_table[2][65536];

FullConeNAT &FullConeNAT::Lookup(ProtocolID protocol, U16 local_port) {
  int protocol_index = protocol == ProtocolID::TCP ? 0 : 1;
  return nat_table[protocol_index][local_port];
}

struct SymmetricNAT : Expirable {
  struct Key {
    IP remote_ip;
    U16 remote_port;
    U16 local_port;

    bool operator==(const Key &other) const {
      return remote_ip == other.remote_ip && remote_port == other.remote_port &&
             local_port == other.local_port;
    }

    Size Hash() const { return *reinterpret_cast<const size_t *>(this); }
  } key;
  IP local_ip;

  struct HashByRemote {
    using is_transparent = std::true_type;

    Size operator()(const SymmetricNAT *n) const { return n->key.Hash(); }
    Size operator()(const Key &key) const { return key.Hash(); }
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

  static std::unordered_set<SymmetricNAT *, HashByRemote, EqualByRemote> table;

  SymmetricNAT(Key key, IP local_ip)
      : Expirable(30min), key(key), local_ip(local_ip) {
    table.insert(this);
  }
  ~SymmetricNAT() { table.erase(this); }
};

std::unordered_set<SymmetricNAT *, SymmetricNAT::HashByRemote,
                   SymmetricNAT::EqualByRemote>
    SymmetricNAT::table;

std::unordered_map<IP, MAC> local_ip_to_mac;

// Using pipes for inter-thread communication is rather inefficient but at the
// time this was written, the epoll namespace didn't had any purely-userspace
// mechanism to do it.
//
// If this ever becomes a performance bottleneck, then one solution might be to
// switch the main thread to wait on a task queue instead of epoll. A secondary
// thread would wait for the epoll events and push them to the task queue.
struct RecordTrafficPipe : epoll::Listener {
  FD write_fd;

  void Setup(Status &status) {
    int pipe_fds[2];
    if (pipe(pipe_fds) == -1) {
      AppendErrorMessage(status) +=
          "Couldn't create pipes for the firewall loop";
      return;
    }
    fd = pipe_fds[0];
    write_fd = pipe_fds[1];
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    epoll::Add(this, status);
  }

  struct RecordTrafficMessage {
    MAC local_host;
    IP remote_ip;
    uint32_t up;
    uint32_t down;
  };

  void NotifyRead(Status &status) override {
    while (true) {
      RecordTrafficMessage msg;
      SSize read_bytes = read(fd, &msg, sizeof(msg));
      if (read_bytes == 0) { // EOF
        epoll::Del(this, status);
        break;
      } else if (read_bytes == -1) { // Nothing to read / Error
        if (errno == EWOULDBLOCK) {
          errno = 0;
          break;
        }
        AppendErrorMessage(status) += "read()";
        epoll::Del(this, status);
        break;
      } else if (read_bytes < sizeof(RecordTrafficMessage)) { // Not enough data
        break;
      } else { // Got a full entry
        RecordTraffic(msg.local_host, msg.remote_ip, msg.up, msg.down);
      }
    }
  }

  // This method should be called from the Firewall thread only.
  void FirewallRecordTraffic(MAC local_mac, IP remote_ip, U32 up, U32 down) {
    RecordTrafficMessage msg{local_mac, remote_ip, up, down};
    write(write_fd, &msg, sizeof(msg));
  }

  const char *Name() const override { return "firewall::RecordTrafficPipe"; }
};

RecordTrafficPipe pipe;

void OnReceive(nfgenmsg &msg, Netlink::Attrs attr_seq) {
  Netlink::Attr *attrs[NFQA_MAX + 1]{};
  for (auto &attr : attr_seq) {
    if (attr.type > NFQA_MAX) {
      continue;
    }
    attrs[attr.type] = &attr;
  }
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
  Span<> payload = attrs[NFQA_PAYLOAD]->Span();
  IP_Header &ip = *(IP_Header *)payload.data();

  bool from_lan = lan_network.Contains(ip.source_ip);
  bool to_lan = lan_network.Contains(ip.destination_ip);
  bool to_internet = !to_lan && (ip.destination_ip != IP(255, 255, 255, 255));
  bool has_ports = ip.proto == ProtocolID::TCP || ip.proto == ProtocolID::UDP;
  bool packet_modified = false;

  INET_Header &inet = *(INET_Header *)(payload.data() + ip.HeaderLength());
  TCP_Header &tcp = *(TCP_Header *)(&inet);
  UDP_Header &udp = *(UDP_Header *)(&inet);

  if constexpr (kLogPackets) {
    Str protocol_string = ToStr(ip.proto);
    if (ip.proto == ProtocolID::TCP) {
      protocol_string +=
          f(" %5d -> %-5d", tcp.source_port, tcp.destination_port);
    } else if (ip.proto == ProtocolID::UDP) {
      protocol_string +=
          f(" %5d -> %-5d", udp.source_port, udp.destination_port);
    }
    U32 packet_id = Big(phdr.packet_id).big_endian;
    LOG << f("#%04x ", packet_id) << f("%15s", ToStr(ip.source_ip).c_str())
        << " => " << f("%-15s", ToStr(ip.destination_ip).c_str()) << " ("
        << protocol_string << "): " << f("%4d", payload.size()) << " B";
  }

  auto &checksum = ip.proto == ProtocolID::TCP ? tcp.checksum : udp.checksum;
  int socket_type = ip.proto == ProtocolID::TCP ? SOCK_STREAM : SOCK_DGRAM;

  Expirable::Expire();

  if (ip.destination_ip == wan_ip && !from_lan && has_ports) {
    // Packet coming to our WAN IP from outside of LAN.
    // We may need to modify the destination (NAT demangling).

    // Attempt to find a matching entry in the Symmetric NAT table.
    auto it = SymmetricNAT::table.find<SymmetricNAT::Key>(
        {ip.source_ip, inet.source_port, inet.destination_port});
    if (it != SymmetricNAT::table.end()) {
      // Found a matching entry. Keep this entry for the next 30 minutes.
      (*it)->UpdateExpiration(30min);
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

    if (packet_modified) {
      auto it = local_ip_to_mac.find(ip.destination_ip);
      if (it != local_ip_to_mac.end()) {
        MAC &mac = it->second;
        pipe.FirewallRecordTraffic(mac, ip.source_ip, 0, payload.size());
      }
    }
  } else if (from_lan && to_internet && ip.source_ip != lan_ip && has_ports) {
    // Packet coming from LAN into the Internet.
    // We have to modify the source (NAT mangling).

    if (attrs[NFQA_HWADDR] != nullptr) {
      nfqnl_msg_packet_hw &hw = attrs[NFQA_HWADDR]->As<nfqnl_msg_packet_hw>();
      MAC &mac = *(MAC *)hw.hw_addr;
      local_ip_to_mac[ip.source_ip] = mac;
      pipe.FirewallRecordTraffic(mac, ip.destination_ip, payload.size(), 0);
    }

    // Record the original source IP in the Full Cone NAT table.
    // New packets from unknown sources will be sent to this LAN IP.
    FullConeNAT &fullcone = FullConeNAT::Lookup(ip.proto, inet.source_port);
    fullcone.lan_host_ip = ip.source_ip;

    // Record the original source IP in the Symmetric NAT table.
    // New packets from this destination will be sent back to this LAN IP.
    auto it = SymmetricNAT::table.find<SymmetricNAT::Key>(
        {ip.destination_ip, inet.destination_port, inet.source_port});
    if (it == SymmetricNAT::table.end()) {
      new SymmetricNAT(SymmetricNAT::Key{ip.destination_ip,
                                         inet.destination_port,
                                         inet.source_port},
                       ip.source_ip);
    } else {
      (*it)->UpdateExpiration(30min);
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
    queue->ReceiveT<NFNL_SUBSYS_QUEUE << 8 | NFQNL_MSG_PACKET, nfgenmsg>(
        OnReceive, status);
    if (!stop && !status.Ok()) {
      status() += "Firewall failed to receive message from kernel";
      ERROR << status;
    }
  }
}

void Start(Status &status) {
  pipe.Setup(status);
  if (!OK(status)) {
    AppendErrorMessage(status) += "Couldn't setup pipe for recording traffic";
    return;
  }

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
  Status status_ignore;
  epoll::Del(&pipe, status_ignore);
}

} // namespace gatekeeper::firewall