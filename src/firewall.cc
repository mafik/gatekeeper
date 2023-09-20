#include "firewall.hh"

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <sys/prctl.h>

#include <optional>
#include <thread>
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

struct NAT_Entry {
  // Note: theoretically we could only store the last two bytes of the IP
  // because our network is /16. This might change in the future though and it's
  // not that much of a saving anyway so let's keep things simple.
  IP lan_host_ip;

  static NAT_Entry &Lookup(ProtocolID protocol, uint16_t local_port);
};

static NAT_Entry nat_table[2][65536];

NAT_Entry &NAT_Entry::Lookup(ProtocolID protocol, uint16_t local_port) {
  int protocol_index = protocol == ProtocolID::TCP ? 0 : 1;
  return nat_table[protocol_index][local_port];
}
void OnReceive(nfgenmsg &msg, std::span<Netlink::Attr *> attrs) {
  if (attrs[NFQA_PACKET_HDR] == nullptr) {
    ERROR << "NFQA_PACKET_HDR is missing";
    return;
  }
  nfqnl_msg_packet_hdr &phdr =
      attrs[NFQA_PACKET_HDR]->As<nfqnl_msg_packet_hdr>();
  if (attrs[NFQA_PAYLOAD] == nullptr) {
    ERROR << "NFQA_PAYLOAD is missing";
    return;
  }
  std::string_view payload = attrs[NFQA_PAYLOAD]->View();
  IP_Header &ip = attrs[NFQA_PAYLOAD]->As<IP_Header>();

  bool interesting = true;

  bool from_net = lan_network.Contains(ip.source_ip);
  bool to_net = lan_network.Contains(ip.destination_ip);

  netfilter::Verdict verdict(phdr.packet_id, true);

  if (from_net == to_net && ip.destination_ip != wan_ip) {
    interesting = false;
  }

  if (ip.proto != ProtocolID::TCP && ip.proto != ProtocolID::UDP) {
    interesting = false;
  }

  if (!interesting) {
    // Let boring packets through
    Status status;
    queue->Send(verdict, status);
    if (!status.Ok()) {
      status() += "Couldn't send verdict";
      ERROR << status;
    }
    return;
  }

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

  if (ip.destination_ip == wan_ip) {
    // Packet coming to our WAN IP. We may need to modify the destination.
    NAT_Entry &entry = NAT_Entry::Lookup(ip.proto, inet.destination_port);
    if (entry.lan_host_ip.addr != 0) {
      ip.destination_ip = entry.lan_host_ip;
      ip.UpdateChecksum();
      UpdateLayer4Checksum(ip, checksum);
      Status status;
      queue->SendWithAttr(verdict, *attrs[NFQA_PAYLOAD], status);
      if (!status.Ok()) {
        status() += "Couldn't send verdict";
        ERROR << status;
      }
      return;
    }
  } else if (from_net && ip.source_ip != lan_ip) {
    // Packet coming from LAN. We may need to modify the source.

    // Record the original source IP
    NAT_Entry &existing_entry = NAT_Entry::Lookup(ip.proto, inet.source_port);
    if (existing_entry.lan_host_ip != ip.source_ip) {
      if (existing_entry.lan_host_ip != 0) {
        LOG << "NAT table collision. Port " << inet.source_port << " already "
            << "mapped to " << existing_entry.lan_host_ip.LoggableString()
            << ", is being remapped to " << ip.source_ip.LoggableString();
      }
      existing_entry.lan_host_ip = ip.source_ip;
    }
    // Mangle the source IP to point back at our WAN IP
    ip.source_ip = wan_ip;
    ip.UpdateChecksum();
    UpdateLayer4Checksum(ip, checksum);

    Status status;
    // Send modified packet
    queue->SendWithAttr(verdict, *attrs[NFQA_PAYLOAD], status);
    if (!status.Ok()) {
      status() += "Couldn't send verdict";
      ERROR << status;
    }
    return;
  }

  Status status;
  queue->Send(verdict, status);
  if (!status.Ok()) {
    status() += "Couldn't send verdict";
    ERROR << status;
  }
}

std::atomic_bool running = true;

void Loop() {
  prctl(PR_SET_NAME, "Firewall loop", 0, 0, 0);
  while (running) {
    Status status;
    queue->ReceiveT<nfgenmsg>(NFNL_SUBSYS_QUEUE << 8 | NFQNL_MSG_PACKET,
                              OnReceive, status);
    if (running && !status.Ok()) {
      status() += "Firewall failed to receive message from kernel";
      ERROR << status;
    }
  }
}

void Start(Status &status) {
  running = true;
  hook.emplace(status);
  if (!status.Ok()) {
    return;
  }

  queue.emplace(NETLINK_NETFILTER, status);
  if (!status.Ok()) {
    return;
  }

  Bind bind;
  queue->Send(bind, status);

  CopyPacket copy_packet;
  queue->Send(copy_packet, status);
  loop = std::thread(Loop);
}

void Stop() {
  running = false;
  queue->fd.Close();
  loop.join();
  queue.reset();
  hook.reset();
}

} // namespace gatekeeper::firewall