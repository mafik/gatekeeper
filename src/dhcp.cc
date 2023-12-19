#include "dhcp.hh"

#include <chrono>
#include <cstring>
#include <sys/socket.h>

#include "arp.hh"
#include "big_endian.hh"
#include "config.hh"
#include "etc.hh"
#include "expirable.hh"
#include "format.hh"
#include "hex.hh"
#include "log.hh"
#include "mac.hh"
#include "memory.hh"
#include "random.hh"
#include "rfc1700.hh"
#include "status.hh"

using namespace std;
using namespace maf;
using chrono::steady_clock;

namespace dhcp {

const IP kBroadcastIP(255, 255, 255, 255);
const U16 kServerPort = 67;
const U16 kClientPort = 68;
const U32 kMagicCookie = 0x63825363;

namespace options {

// RFC 2132
enum class OptionCode : U8 {
  Pad = 0,
  SubnetMask = 1,
  TimeOffset = 2,
  Router = 3,
  TimeServer = 4,
  NameServer = 5,
  DomainNameServer = 6,
  LogServer = 7,
  CookieServer = 8,
  LPRServer = 9,
  ImpressServer = 10,
  ResourceLocationServer = 11,
  HostName = 12,
  BootFileSize = 13,
  MeritDumpFile = 14,
  DomainName = 15,
  SwapServer = 16,
  RootPath = 17,
  ExtensionsPath = 18,
  IPForwarding = 19,
  NonLocalSourceRouting = 20,
  PolicyFilter = 21,
  MaximumDatagramReassemblySize = 22,
  DefaultIPTimeToLive = 23,
  PathMTUAgingTimeout = 24,
  PathMTUPlateauTable = 25,
  InterfaceMTU = 26,
  AllSubnetsAreLocal = 27,
  BroadcastAddress = 28,
  PerformMaskDiscovery = 29,
  MaskSupplier = 30,
  PerformRouterDiscovery = 31,
  RouterSolicitationAddress = 32,
  StaticRoute = 33,
  TrailerEncapsulation = 34,
  ARPCacheTimeout = 35,
  EthernetEncapsulation = 36,
  TCPDefaultTTL = 37,
  TCPKeepaliveInterval = 38,
  TCPKeepaliveGarbage = 39,
  NetworkInformationServiceDomain = 40,
  NetworkInformationServers = 41,
  NTPServers = 42,
  VendorSpecificInformation = 43,
  NetBIOSOverTCPIPNameServer = 44,
  NetBIOSOverTCPIPDatagramDistributionServer = 45,
  NetBIOSOverTCPIPNodeType = 46,
  NetBIOSOverTCPIPScope = 47,
  XWindowSystemFontServer = 48,
  XWindowSystemDisplayManager = 49,
  RequestedIPAddress = 50,
  IPAddressLeaseTime = 51,
  Overload = 52,
  MessageType = 53,
  ServerIdentifier = 54,
  ParameterRequestList = 55,
  Message = 56,
  MaximumDHCPMessageSize = 57,
  RenewalTimeValue = 58,
  RebindingTimeValue = 59,
  VendorClassIdentifier = 60,
  ClientIdentifier = 61,
  NetworkInformationServicePlusDomain = 64,
  NetworkInformationServicePlusServers = 65,
  TFTPServerName = 66,
  BootfileName = 67,
  MobileIPHomeAgent = 68,
  SimpleMailTransportProtocol = 69,
  PostOfficeProtocolServer = 70,
  NetworkNewsTransportProtocol = 71,
  DefaultWorldWideWebServer = 72,
  DefaultFingerServer = 73,
  DefaultInternetRelayChatServer = 74,
  StreetTalkServer = 75,
  StreetTalkDirectoryAssistance = 76,
  DomainSearch = 119,
  ClasslessStaticRoute = 121,
  PrivateClasslessStaticRoute = 249,
  PrivateProxyAutoDiscovery = 252,
  End = 255,
};

Str ToStr(OptionCode code) {
  switch (code) {
  case OptionCode::Pad:
    return "Pad";
  case OptionCode::SubnetMask:
    return "Subnet Mask";
  case OptionCode::TimeOffset:
    return "Time Offset";
  case OptionCode::Router:
    return "Router";
  case OptionCode::TimeServer:
    return "Time Server";
  case OptionCode::NameServer:
    return "Name Server";
  case OptionCode::DomainNameServer:
    return "Domain Name Server";
  case OptionCode::LogServer:
    return "Log Server";
  case OptionCode::CookieServer:
    return "Cookie Server";
  case OptionCode::LPRServer:
    return "LPR Server";
  case OptionCode::ImpressServer:
    return "Impress Server";
  case OptionCode::ResourceLocationServer:
    return "Resource Location Server";
  case OptionCode::HostName:
    return "Host Name";
  case OptionCode::BootFileSize:
    return "Boot File Size";
  case OptionCode::MeritDumpFile:
    return "Merit Dump File";
  case OptionCode::DomainName:
    return "Domain Name";
  case OptionCode::SwapServer:
    return "Swap Server";
  case OptionCode::RootPath:
    return "Root Path";
  case OptionCode::ExtensionsPath:
    return "Extensions Path";
  case OptionCode::IPForwarding:
    return "IP Forwarding Enable/Disable";
  case OptionCode::NonLocalSourceRouting:
    return "Non-Local Source Routing Enable/Disable";
  case OptionCode::PolicyFilter:
    return "Policy Filter";
  case OptionCode::MaximumDatagramReassemblySize:
    return "Maximum Datagram Reassembly Size";
  case OptionCode::DefaultIPTimeToLive:
    return "Default IP Time To Live";
  case OptionCode::PathMTUAgingTimeout:
    return "Path MTU Aging Timeout";
  case OptionCode::PathMTUPlateauTable:
    return "Path MTU Plateau Table";
  case OptionCode::InterfaceMTU:
    return "Interface MTU";
  case OptionCode::AllSubnetsAreLocal:
    return "All Subnets Are Local";
  case OptionCode::BroadcastAddress:
    return "Broadcast Address";
  case OptionCode::PerformMaskDiscovery:
    return "Perform Mask Discovery";
  case OptionCode::MaskSupplier:
    return "Mask Supplier";
  case OptionCode::PerformRouterDiscovery:
    return "Perform Router Discovery";
  case OptionCode::RouterSolicitationAddress:
    return "Router Solicitation Address";
  case OptionCode::StaticRoute:
    return "Static Route";
  case OptionCode::TrailerEncapsulation:
    return "Trailer Encapsulation";
  case OptionCode::ARPCacheTimeout:
    return "ARP Cache Timeout";
  case OptionCode::EthernetEncapsulation:
    return "Ethernet Encapsulation";
  case OptionCode::TCPDefaultTTL:
    return "TCP Default TTL";
  case OptionCode::TCPKeepaliveInterval:
    return "TCP Keepalive Interval";
  case OptionCode::TCPKeepaliveGarbage:
    return "TCP Keepalive Garbage";
  case OptionCode::NetworkInformationServiceDomain:
    return "Network Information Service Domain";
  case OptionCode::NetworkInformationServers:
    return "Network Information Servers";
  case OptionCode::NTPServers:
    return "NTP Servers";
  case OptionCode::VendorSpecificInformation:
    return "Vendor Specific Information";
  case OptionCode::NetBIOSOverTCPIPNameServer:
    return "NetBIOS over TCP/IP Name Server";
  case OptionCode::NetBIOSOverTCPIPDatagramDistributionServer:
    return "NetBIOS over TCP/IP Datagram Distribution Server";
  case OptionCode::NetBIOSOverTCPIPNodeType:
    return "NetBIOS over TCP/IP Node Type";
  case OptionCode::NetBIOSOverTCPIPScope:
    return "NetBIOS over TCP/IP Scope";
  case OptionCode::XWindowSystemFontServer:
    return "X Window System Font Server";
  case OptionCode::XWindowSystemDisplayManager:
    return "X Window System Display Manager";
  case OptionCode::RequestedIPAddress:
    return "Requested IP Address";
  case OptionCode::IPAddressLeaseTime:
    return "IP Address Lease Time";
  case OptionCode::Overload:
    return "Overload";
  case OptionCode::MessageType:
    return "Message Type";
  case OptionCode::ServerIdentifier:
    return "Server Identifier";
  case OptionCode::ParameterRequestList:
    return "Parameter Request List";
  case OptionCode::Message:
    return "Message";
  case OptionCode::MaximumDHCPMessageSize:
    return "Maximum DHCP Message Size";
  case OptionCode::RenewalTimeValue:
    return "Renewal (T1) Time Value";
  case OptionCode::RebindingTimeValue:
    return "Rebinding (T2) Time Value";
  case OptionCode::VendorClassIdentifier:
    return "Vendor Class Identifier";
  case OptionCode::ClientIdentifier:
    return "Client Identifier";
  case OptionCode::NetworkInformationServicePlusDomain:
    return "Network Information Service+ Domain";
  case OptionCode::NetworkInformationServicePlusServers:
    return "Network Information Service+ Servers";
  case OptionCode::TFTPServerName:
    return "TFTP Server Name";
  case OptionCode::BootfileName:
    return "Bootfile Name";
  case OptionCode::MobileIPHomeAgent:
    return "Mobile IP Home Agent";
  case OptionCode::SimpleMailTransportProtocol:
    return "Simple Mail Transport Protocol";
  case OptionCode::PostOfficeProtocolServer:
    return "Post Office Protocol Server";
  case OptionCode::NetworkNewsTransportProtocol:
    return "Network News Transport Protocol";
  case OptionCode::DefaultWorldWideWebServer:
    return "Default World Wide Web Server";
  case OptionCode::DefaultFingerServer:
    return "Default Finger Server";
  case OptionCode::DefaultInternetRelayChatServer:
    return "Default Internet Relay Chat Server";
  case OptionCode::StreetTalkServer:
    return "StreetTalk Server";
  case OptionCode::StreetTalkDirectoryAssistance:
    return "StreetTalk Directory Assistance";
  case OptionCode::DomainSearch:
    return "Domain Search";
  case OptionCode::ClasslessStaticRoute:
    return "Classless Static Route";
  case OptionCode::PrivateClasslessStaticRoute:
    return "Private/Classless Static Route (Microsoft)";
  case OptionCode::PrivateProxyAutoDiscovery:
    return "Private/Proxy autodiscovery";
  case OptionCode::End:
    return "End";
  default:
    return "Unknown option code " + ::ToStr((int)code);
  }
}

struct __attribute__((__packed__)) Base {
  OptionCode code;
  U8 length;
  Base(OptionCode code, U8 length = 0) : code(code), length(length) {}
  Str ToStr() const;
  size_t size() const {
    switch (code) {
    case OptionCode::Pad:
    case OptionCode::End:
      return 1;
    default:
      return sizeof(*this) + length;
    }
  }
  void write_to(string &buffer) const {
    buffer.append((const char *)this, size());
  }
};

struct __attribute__((__packed__)) SubnetMask : Base {
  const IP ip;
  SubnetMask(const IP &ip) : Base(OptionCode::SubnetMask, 4), ip(ip) {}
  Str ToStr() const { return "SubnetMask(" + ::ToStr(ip) + ")"; }
};

static_assert(sizeof(SubnetMask) == 6, "SubnetMask is not packed correctly");

struct __attribute__((__packed__)) Router : Base {
  const IP ip;
  Router(const IP &ip) : Base(OptionCode::Router, 4), ip(ip) {}
  Str ToStr() const { return "Router(" + ::ToStr(ip) + ")"; }
};

struct __attribute__((__packed__)) DomainNameServer : Base {
  IP dns[0];
  static unique_ptr<DomainNameServer, FreeDeleter>
  Make(initializer_list<IP> ips) {
    int n = ips.size();
    void *buffer = malloc(sizeof(DomainNameServer) + sizeof(IP) * n);
    auto r = unique_ptr<DomainNameServer, FreeDeleter>(new (buffer)
                                                           DomainNameServer(n));
    int i = 0;
    for (auto ip : ips) {
      r->dns[i++] = ip;
    }
    return r;
  }
  Str ToStr() const {
    int n = length / 4;
    Str r = "DomainNameServer(";
    for (int i = 0; i < n; ++i) {
      if (i > 0) {
        r += ", ";
      }
      r += ::ToStr(dns[i]);
    }
    r += ")";
    return r;
  }

private:
  DomainNameServer(int dns_count)
      : Base(OptionCode::DomainNameServer, 4 * dns_count) {}
};

struct __attribute__((__packed__)) HostName : Base {
  static constexpr OptionCode kCode = OptionCode::HostName;
  const U8 value[];
  HostName() = delete;
  Str ToStr() const { return "HostName(" + hostname() + ")"; }
  Str hostname() const { return std::string((const char *)value, length); }
};

struct __attribute__((__packed__)) DomainName : Base {
  static constexpr OptionCode kCode = OptionCode::DomainName;
  const U8 value[];
  static unique_ptr<DomainName, FreeDeleter> Make(string domain_name) {
    int n = domain_name.size();
    void *buffer = malloc(sizeof(DomainName) + n);
    auto r = unique_ptr<DomainName, FreeDeleter>(new (buffer) DomainName(n));
    memcpy((void *)r->value, domain_name.data(), n);
    return r;
  }
  Str domain_name() const { return Str((const char *)value, length); }
  Str ToStr() const { return "DomainName(" + domain_name() + ")"; }

private:
  DomainName(int length) : Base(kCode, length) {}
};

struct __attribute__((__packed__)) RequestedIPAddress : Base {
  static constexpr OptionCode kCode = OptionCode::RequestedIPAddress;
  const IP ip;
  RequestedIPAddress(const IP &ip) : Base(kCode, 4), ip(ip) {}
  Str ToStr() const { return "RequestedIPAddress(" + ::ToStr(ip) + ")"; }
};

struct __attribute__((__packed__)) IPAddressLeaseTime : Base {
  const Big<U32> seconds;
  IPAddressLeaseTime(U32 seconds)
      : Base(OptionCode::IPAddressLeaseTime, 4), seconds(seconds) {}
  Str ToStr() const { return "IPAddressLeaseTime(" + ::ToStr(seconds) + ")"; }
};

struct __attribute__((__packed__)) MessageType : Base {
  enum class Value : U8 {
    UNKNOWN = 0,
    DISCOVER = 1,
    OFFER = 2,
    REQUEST = 3,
    DECLINE = 4,
    ACK = 5,
    NAK = 6,
    RELEASE = 7,
    INFORM = 8,
    FORCERENEW = 9,
    LEASEQUERY = 10,
    LEASEUNASSIGNED = 11,
    LEASEUNKNOWN = 12,
    LEASEACTIVE = 13,
    BULKLEASEQUERY = 14,
    LEASEQUERYDONE = 15,
    ACTIVELEASEQUERY = 16,
    LEASEQUERYSTATUS = 17,
    TLS = 18,
    VALUE_COUNT = 19,
  };
  const Value value;
  MessageType(Value value) : Base(OptionCode::MessageType, 1), value(value) {}
  Str ToStr() const;
};

Str ToStr(MessageType::Value value) {
  switch (value) {
  case MessageType::Value::UNKNOWN:
    return "UNKNOWN";
  case MessageType::Value::DISCOVER:
    return "DISCOVER";
  case MessageType::Value::OFFER:
    return "OFFER";
  case MessageType::Value::REQUEST:
    return "REQUEST";
  case MessageType::Value::DECLINE:
    return "DECLINE";
  case MessageType::Value::ACK:
    return "ACK";
  case MessageType::Value::NAK:
    return "NAK";
  case MessageType::Value::RELEASE:
    return "RELEASE";
  case MessageType::Value::INFORM:
    return "INFORM";
  case MessageType::Value::FORCERENEW:
    return "FORCERENEW";
  case MessageType::Value::LEASEQUERY:
    return "LEASEQUERY";
  case MessageType::Value::LEASEUNASSIGNED:
    return "LEASEUNASSIGNED";
  case MessageType::Value::LEASEUNKNOWN:
    return "LEASEUNKNOWN";
  case MessageType::Value::LEASEACTIVE:
    return "LEASEACTIVE";
  case MessageType::Value::BULKLEASEQUERY:
    return "BULKLEASEQUERY";
  case MessageType::Value::LEASEQUERYDONE:
    return "LEASEQUERYDONE";
  case MessageType::Value::ACTIVELEASEQUERY:
    return "ACTIVELEASEQUERY";
  case MessageType::Value::LEASEQUERYSTATUS:
    return "LEASEQUERYSTATUS";
  case MessageType::Value::TLS:
    return "TLS";
  default:
    return ::ToStr((int)value);
  }
}

Str MessageType::ToStr() const {
  return "MessageType(" + options::ToStr(value) + ")";
}

struct __attribute__((__packed__)) ServerIdentifier : Base {
  const IP ip;
  ServerIdentifier(const IP &ip)
      : Base(OptionCode::ServerIdentifier, 4), ip(ip) {}
  Str ToStr() const { return "ServerIdentifier(" + ::ToStr(ip) + ")"; }
};

// RFC 2132, section 9.8
struct __attribute__((__packed__)) ParameterRequestList {
  const U8 code = 55;
  const U8 length;
  const OptionCode c[0];
  Str ToStr() const {
    Str r = "ParameterRequestList(";
    for (int i = 0; i < length; ++i) {
      r += "\n  ";
      r += options::ToStr(c[i]);
    }
    r += ")";
    return r;
  }
};

// RFC 2132, section 9.10
struct __attribute__((__packed__)) MaximumDHCPMessageSize {
  const U8 code = 57;
  const U8 length = 2;
  const Big<U16> value = 1500;
  Str ToStr() const { return "MaximumDHCPMessageSize(" + ::ToStr(value) + ")"; }
};

struct __attribute__((__packed__)) VendorClassIdentifier {
  const U8 code = 60;
  const U8 length;
  const U8 value[0];
  Str ToStr() const {
    return "VendorClassIdentifier(" + Str((const char *)value, length) + ")";
  }
};

// RFC 2132, Section 9.14
struct __attribute__((__packed__)) ClientIdentifier : Base {
  static constexpr OptionCode kCode = OptionCode::ClientIdentifier;
  const U8 type = 1; // Hardware address
  const MAC hardware_address;
  ClientIdentifier(const MAC &hardware_address)
      : Base(kCode, 1 + 6), hardware_address(hardware_address) {}
  Str ToStr() const {
    Str r = "ClientIdentifier(";
    r += rfc1700::HardwareTypeToStr(type);
    r += ", " + hardware_address.ToStr() + ")";
    return r;
  }
};

struct __attribute__((__packed__)) End : Base {
  End() : Base(OptionCode::End) {}
};

Str Base::ToStr() const {
  switch (code) {
  case OptionCode::SubnetMask:
    return ((const options::SubnetMask *)this)->ToStr();
  case OptionCode::Router:
    return ((const options::Router *)this)->ToStr();
  case OptionCode::DomainNameServer:
    return ((const options::DomainNameServer *)this)->ToStr();
  case OptionCode::HostName:
    return ((const options::HostName *)this)->ToStr();
  case OptionCode::DomainName:
    return ((const options::DomainName *)this)->ToStr();
  case OptionCode::RequestedIPAddress:
    return ((const options::RequestedIPAddress *)this)->ToStr();
  case OptionCode::IPAddressLeaseTime:
    return ((const options::IPAddressLeaseTime *)this)->ToStr();
  case OptionCode::MessageType:
    return ((const options::MessageType *)this)->ToStr();
  case OptionCode::ServerIdentifier:
    return ((const options::ServerIdentifier *)this)->ToStr();
  case OptionCode::ParameterRequestList:
    return ((const options::ParameterRequestList *)this)->ToStr();
  case OptionCode::MaximumDHCPMessageSize:
    return ((const options::MaximumDHCPMessageSize *)this)->ToStr();
  case OptionCode::VendorClassIdentifier:
    return ((const options::VendorClassIdentifier *)this)->ToStr();
  case OptionCode::ClientIdentifier:
    return ((const options::ClientIdentifier *)this)->ToStr();
  default:
    const char *data = (const char *)(this) + sizeof(*this);
    return "\"" + options::ToStr(code) + "\" " + ::ToStr(length) +
           " bytes: " + BytesToHex(Span<>(data, length));
  }
}

} // namespace options

// Fixed prefix of a DHCP packet. This is followed by a list of options.
// All fields use network byte order.
struct __attribute__((__packed__)) Header {
  U8 message_type = 1;  // Boot Request
  U8 hardware_type = 1; // Ethernet
  U8 hardware_address_length = 6;
  U8 hops = 0;
  U32 transaction_id = random<U32>();
  U16 seconds_elapsed = 0;
  Big<U16> flags = 0;
  IP client_ip = {0, 0, 0, 0};  // ciaddr
  IP your_ip = {0, 0, 0, 0};    // yiaddr
  IP server_ip = {0, 0, 0, 0};  // siaddr (Next server IP)
  IP gateway_ip = {0, 0, 0, 0}; // giaddr (Relay agent IP)
  union {
    U8 client_hardware_address[16] = {};
    MAC client_mac_address;
  };
  U8 server_name[64] = {};
  U8 boot_filename[128] = {};
  Big<U32> magic_cookie = kMagicCookie;

  Str ToStr() const {
    string s = "dhcp::Header {\n";
    s += "  message_type: " + ::ToStr(message_type) + "\n";
    s += "  hardware_type: " + rfc1700::HardwareTypeToStr(hardware_type) + "\n";
    s +=
        "  hardware_address_length: " + ::ToStr(hardware_address_length) + "\n";
    s += "  hops: " + ::ToStr(hops) + "\n";
    s += "  transaction_id: " + ValToHex(transaction_id) + "\n";
    s += "  seconds_elapsed: " + ::ToStr(seconds_elapsed) + "\n";
    s += "  flags: " + ::ToStr(flags) + "\n";
    s += "  client_ip: " + ::ToStr(client_ip) + "\n";
    s += "  your_ip: " + ::ToStr(your_ip) + "\n";
    s += "  server_ip: " + ::ToStr(server_ip) + "\n";
    s += "  gateway_ip: " + ::ToStr(gateway_ip) + "\n";
    s += "  client_mac_address: " + client_mac_address.ToStr() + "\n";
    s += "  server_name: " + std::string((const char *)server_name) + "\n";
    s += "  boot_filename: " + std::string((const char *)boot_filename) + "\n";
    s += "  magic_cookie: " + ValToHex(magic_cookie) + "\n";
    s += "}";
    return s;
  }

  void write_to(Str &buffer) {
    buffer.append((const char *)this, sizeof(*this));
  }
};

// Provides read access to a memory buffer that contains a DHCP packet.
struct __attribute__((__packed__)) PacketView : Header {
  U8 options[0];
  void CheckFitsIn(size_t len, string &error) {
    if (len < sizeof(Header)) {
      error = "Packet is too short";
      return;
    }
    if (len < sizeof(Header) + 1) {
      error = "Packet is too short to contain an End option";
      return;
    }
    U8 *p = options;
    while (true) {
      options::Base *opt = (options::Base *)p;
      p += opt->size();
      if (opt->code == options::OptionCode::End) {
        break;
      }
    }
    size_t options_size = p - options;
    size_t total_size = sizeof(Header) + options_size;
    if (len < total_size) {
      error = "Packet is too short to contain all the options";
      return;
    }
    // Packets can be padded with 0s at the end - we can ignore them.
  }
  Str ToStr() const {
    Str s = "dhcp::PacketView {\n";
    s += IndentString(Header::ToStr());
    s += "\n  options:\n";
    const U8 *p = options;
    while (*p != 255) {
      const options::Base &opt = *(const options::Base *)p;
      s += IndentString(opt.ToStr(), 4) + "\n";
      p += opt.size();
    }
    s += "}";
    return s;
  }
  options::Base *FindOption(options::OptionCode code) const {
    const U8 *p = options;
    while (*p != 255) {
      options::Base &opt = *(options::Base *)p;
      if (opt.code == code) {
        return &opt;
      }
      p += opt.size();
    }
    return nullptr;
  }
  template <class T> T *FindOption() const {
    options::Base *base = FindOption(T::kCode);
    if (base) {
      return (T *)base;
    }
    return nullptr;
  }
  options::MessageType::Value MessageType() const {
    if (options::MessageType *o = (options::MessageType *)FindOption(
            options::OptionCode::MessageType)) {
      return o->value;
    }
    return options::MessageType::Value::UNKNOWN;
  }
  MAC effective_mac() const {
    if (auto *opt = FindOption<options::ClientIdentifier>()) {
      return opt->hardware_address;
    }
    return client_mac_address;
  }
};

// Function used to validate IP addresses provided by clients.
bool IsValidClientIP(IP requested_ip) {
  if (!lan_network.Contains(requested_ip)) {
    // Requested IP outside of our network.
    return false;
  }
  if (requested_ip == lan_network.ip) {
    // Requested IP is the network address.
    return false;
  }
  if (requested_ip == lan_network.BroadcastIP()) {
    // Requested IP is the broadcast address.
    return false;
  }
  if (requested_ip == lan_ip) {
    // Requested IP is our own IP.
    return false;
  }
  return true;
}

IP ChooseIP(Server &server, const PacketView &request, string &error) {
  MAC mac = request.effective_mac();
  // Try to find entry with matching client_id.
  if (auto it = server.entries_by_mac.find(mac);
      it != server.entries_by_mac.end()) {
    return (*it)->ip;
  }
  // Take the requested IP if it is available.
  if (auto *opt = request.FindOption<options::RequestedIPAddress>()) {
    const IP requested_ip = opt->ip;
    bool ok = IsValidClientIP(requested_ip);
    if (auto it = server.entries_by_ip.find(requested_ip);
        it != server.entries_by_ip.end()) {
      Server::Entry *entry = *it;
      if ((entry->mac != mac) &&
          (entry->expiration ? entry->expiration > steady_clock::now()
                             : true)) {
        // Requested IP is taken by another client.
        ok = false;
      }
    }
    if (ok) {
      return requested_ip;
    }
  }
  // Try to find unused IP.
  for (IP ip = lan_network.ip + 1; ip < lan_network.BroadcastIP(); ++ip) {
    if (ip == lan_ip) {
      continue;
    }

    if (not server.entries_by_ip.contains(ip)) {
      return ip;
    }
  }
  // Try to find the most expired IP.
  IP oldest_ip(0, 0, 0, 0);
  steady_clock::time_point oldest_expiration = steady_clock::time_point::max();
  for (auto *entry : server.entries_by_ip) {
    if (entry->expiration && *entry->expiration < oldest_expiration) {
      oldest_ip = entry->ip;
      oldest_expiration = *entry->expiration;
    }
  }
  if (oldest_expiration < steady_clock::now()) {
    return oldest_ip;
  }
  error = "No IP available";
  return IP(0, 0, 0, 0);
}

IP ChooseInformIP(const PacketView &request, string &error) {
  IP ip = request.client_ip;
  if (!IsValidClientIP(ip)) {
    error = "Invalid IP address";
    return IP(0, 0, 0, 0);
  }
  return ip;
}

Server server;

Server::Entry::Entry(Server &server, IP ip, MAC mac, Str hostname)
    : Expirable(chrono::steady_clock::time_point::max()), ip(ip), mac(mac),
      hostname(hostname) {
  server.entries_by_ip.insert(this);
  server.entries_by_mac.insert(this);
}

Server::Entry::Entry(Server &server, IP ip, MAC mac, Str hostname,
                     chrono::steady_clock::duration ttl)
    : Expirable(ttl), ip(ip), mac(mac), hostname(hostname) {
  server.entries_by_ip.insert(this);
  server.entries_by_mac.insert(this);
}

void Server::Entry::UpdateMAC(MAC new_mac) {
  server.entries_by_mac.erase(this);
  mac = new_mac;
  server.entries_by_mac.insert(this);
}

void Server::Entry::UpdateIP(IP new_ip) {
  server.entries_by_ip.erase(this);
  ip = new_ip;
  server.entries_by_ip.insert(this);
}

Server::Entry::~Entry() {
  server.entries_by_ip.erase(this);
  server.entries_by_mac.erase(this);
}

void Server::Init() {
  static bool initialized = false;
  if (initialized) {
    return;
  }
  initialized = true;
  for (auto [mac, ip] : etc::ethers) {
    Str hostname = "";
    if (auto etc_hosts_it = etc::hosts.find(ip);
        etc_hosts_it != etc::hosts.end()) {
      auto &aliases = etc_hosts_it->second;
      if (!aliases.empty()) {
        hostname = aliases[0];
      }
    }
    // Static entries never expire. No need to track them.
    new Entry(*this, ip, mac, hostname);
  }
  if (auto it = entries_by_ip.find(lan_ip); it != entries_by_ip.end()) {
    MAC lan_mac = MAC::FromInterface(lan.name);
    (*it)->UpdateMAC(lan_mac);
  } else {
    new Entry(*this, lan_ip, MAC::FromInterface(lan.name), etc::hostname);
  }
}
int AvailableIPs(const Server &server) {
  int zeros = lan_network.Zeros();
  // 3 IPs are reserved: network, broadcast, and server.
  return (1 << zeros) - server.entries_by_ip.size() - 3;
}
void Server::Listen(Status &status) {
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

void Server::StopListening() {
  Status ignored;
  epoll::Del(this, ignored);
  shutdown(fd, SHUT_RDWR);
  close(fd);
}

void Server::HandleRequest(string_view buf, IP source_ip, U16 port) {
  if (buf.size() < sizeof(PacketView)) {
    ERROR << "DHCP server received a packet that is too short: " << buf.size()
          << " bytes:\n"
          << BytesToHex(buf);
    return;
  }
  PacketView &packet = *(PacketView *)buf.data();
  string log_error;
  packet.CheckFitsIn(buf.size(), log_error);
  if (!log_error.empty()) {
    ERROR << log_error;
    return;
  }
  if (packet.magic_cookie != kMagicCookie) {
    ERROR << "DHCP server received a packet with an invalid magic cookie: "
          << ValToHex(packet.magic_cookie);
    return;
  }
  if ((packet.server_ip <=> lan_ip != 0) &&
      (packet.server_ip <=> IP(0, 0, 0, 0) != 0)) {
    // Silently ignore packets that are not for us.
    return;
  }

  options::MessageType::Value response_type =
      options::MessageType::Value::UNKNOWN;
  steady_clock::duration lease_time = 0s;
  bool inform = false;

  const IP chosen_ip =
      inform ? IP(0, 0, 0, 0) : ChooseIP(*this, packet, log_error);
  if (!log_error.empty()) {
    ERROR << log_error << "\n" << packet.ToStr();
    return;
  }

  if (auto it = entries_by_mac.find(packet.effective_mac());
      it != entries_by_mac.end()) {
    auto *entry = *it;
    entry->last_activity = steady_clock::now();
  }

  int request_lease_time_seconds = 60;
  switch (packet.MessageType()) {
  case options::MessageType::Value::DISCOVER:
    response_type = options::MessageType::Value::OFFER;
    lease_time = 10s;
    break;
  case options::MessageType::Value::REQUEST:
    if (auto *opt = packet.FindOption<options::RequestedIPAddress>();
        opt != nullptr && opt->ip != chosen_ip) {
      response_type = options::MessageType::Value::NAK;
    } else {
      response_type = options::MessageType::Value::ACK;
    }
    lease_time = request_lease_time_seconds * 1s;
    break;
  case options::MessageType::Value::INFORM:
    response_type = options::MessageType::Value::ACK;
    lease_time = 0s;
    inform = true;
    break;
  case options::MessageType::Value::RELEASE:
    if (auto it = entries_by_ip.find(packet.client_ip);
        it != entries_by_ip.end()) {
      auto *entry = *it;
      if (entry->mac == packet.effective_mac()) {
        delete entry;
      }
    }
    return;
  default:
    response_type = options::MessageType::Value::UNKNOWN;
    break;
  }

  if (inform && source_ip != packet.client_ip && source_ip != IP(0, 0, 0, 0)) {
    ERROR << "DHCP server received an INFORM packet with a mismatching "
             "source IP: "
          << ToStr(source_ip) << " (source IP) vs " << ToStr(packet.client_ip)
          << " (DHCP client_ip)" << "\n"
          << packet.ToStr();
    return;
  }

  IP response_ip = inform ? packet.client_ip : chosen_ip;
  if (!IsValidClientIP(response_ip)) {
    ERROR << "DHCP server received a packet with an invalid response IP: "
          << ToStr(response_ip) << "\n"
          << packet.ToStr();
    return;
  }

  if (source_ip == IP(0, 0, 0, 0)) {
    // Set client MAC in the ARP table
    Status status;
    arp::Set(lan.name, response_ip, packet.client_mac_address, fd, status);
    if (!OK(status)) {
      AppendErrorMessage(status) +=
          "Failed to set the client IP/MAC association in the system ARP table";
      AppendErrorAdvice(status,
                        "This may happen when the server is under "
                        "a denial of service attack. You may identify where "
                        "the attack comes from by unplugging LAN devices one "
                        "by one until the error stops coming up.");
      ERROR << status;
      return;
    }
  }

  if (response_type == options::MessageType::Value::UNKNOWN) {
    LOG << "DHCP server received unknown DHCP message:\n" << packet.ToStr();
    return;
  }

  // Build response
  string buffer;
  Header{.message_type = 2, // Boot Reply
         .transaction_id = packet.transaction_id,
         .your_ip = chosen_ip,
         .server_ip = lan_ip,
         .client_mac_address = packet.client_mac_address}
      .write_to(buffer);

  options::MessageType(response_type).write_to(buffer);
  options::SubnetMask(lan_network.netmask).write_to(buffer);
  options::Router(lan_ip).write_to(buffer);
  if (lease_time > 0s) {
    options::IPAddressLeaseTime(request_lease_time_seconds).write_to(buffer);
  }
  options::DomainName::Make(kLocalDomain)->write_to(buffer);
  options::ServerIdentifier(lan_ip).write_to(buffer);
  options::DomainNameServer::Make({lan_ip})->write_to(buffer);
  options::End().write_to(buffer);

  fd.SendTo(response_ip, kClientPort, buffer, log_error);
  if (!log_error.empty()) {
    ERROR << log_error;
    return;
  }

  if (!inform) {
    Str hostname = "";
    if (auto opt = packet.FindOption<options::HostName>()) {
      hostname = opt->hostname();
    }
    // Check existing entries for a matching IP or MAC.
    Entry *entry_from_mac = nullptr;
    Entry *entry_from_ip = nullptr;
    if (auto it = entries_by_mac.find(packet.effective_mac());
        it != entries_by_mac.end()) {
      entry_from_mac = *it;
    }
    if (auto it = entries_by_ip.find(chosen_ip); it != entries_by_ip.end()) {
      entry_from_ip = *it;
    }
    // Merge entries if needed.
    Entry *entry = nullptr;
    if (entry_from_ip == entry_from_mac) {
      if (entry_from_mac != nullptr) {
        entry = entry_from_mac;
      } else {
        entry =
            new Entry(*this, chosen_ip, packet.effective_mac(), hostname, 24h);
      }
    } else if (entry_from_mac == nullptr) {
      entry = entry_from_ip;
      entry->UpdateMAC(packet.effective_mac());
    } else if (entry_from_ip == nullptr) {
      entry = entry_from_mac;
      entry->UpdateIP(chosen_ip);
    } else {
      entry = entry_from_mac;
      entry->UpdateIP(chosen_ip);
      delete entry_from_ip;
    }
    // Update the entry.
    entry->hostname = hostname;
    entry->last_activity = steady_clock::now();
    if (entry->expiration.has_value()) {
      entry->UpdateExpiration(24h);
    }
  }
}
const char *Server::Name() const { return "dhcp::Server"; }

Table table;

Table::Table()
    : webui::Table("dhcp", "DHCP", {"Assigned IPs", "Available IPs"}) {}
int Table::Size() const { return 1; }
void Table::Get(int row, int col, string &out) const {
  switch (col) {
  case 0:
    out = f("%d", server.entries_by_ip.size());
    break;
  case 1:
    out = f("%d", AvailableIPs(server));
    break;
  }
}
std::string Table::RowID(int row) const { return "dhcp-onlyrow"; }

} // namespace dhcp