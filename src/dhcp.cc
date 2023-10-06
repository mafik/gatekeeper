#include "dhcp.hh"

#include <cstring>

#include "arp.hh"
#include "config.hh"
#include "etc.hh"
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
const uint16_t kServerPort = 67;
const uint16_t kClientPort = 68;
const uint32_t kMagicCookie = 0x63825363;

namespace options {

// RFC 2132
enum OptionCode : uint8_t {
  OptionCode_Pad = 0,
  OptionCode_SubnetMask = 1,
  OptionCode_TimeOffset = 2,
  OptionCode_Router = 3,
  OptionCode_TimeServer = 4,
  OptionCode_NameServer = 5,
  OptionCode_DomainNameServer = 6,
  OptionCode_LogServer = 7,
  OptionCode_CookieServer = 8,
  OptionCode_LPRServer = 9,
  OptionCode_ImpressServer = 10,
  OptionCode_ResourceLocationServer = 11,
  OptionCode_HostName = 12,
  OptionCode_BootFileSize = 13,
  OptionCode_MeritDumpFile = 14,
  OptionCode_DomainName = 15,
  OptionCode_SwapServer = 16,
  OptionCode_RootPath = 17,
  OptionCode_ExtensionsPath = 18,
  OptionCode_IPForwarding = 19,
  OptionCode_NonLocalSourceRouting = 20,
  OptionCode_PolicyFilter = 21,
  OptionCode_MaximumDatagramReassemblySize = 22,
  OptionCode_DefaultIPTimeToLive = 23,
  OptionCode_PathMTUAgingTimeout = 24,
  OptionCode_PathMTUPlateauTable = 25,
  OptionCode_InterfaceMTU = 26,
  OptionCode_AllSubnetsAreLocal = 27,
  OptionCode_BroadcastAddress = 28,
  OptionCode_PerformMaskDiscovery = 29,
  OptionCode_MaskSupplier = 30,
  OptionCode_PerformRouterDiscovery = 31,
  OptionCode_RouterSolicitationAddress = 32,
  OptionCode_StaticRoute = 33,
  OptionCode_TrailerEncapsulation = 34,
  OptionCode_ARPCacheTimeout = 35,
  OptionCode_EthernetEncapsulation = 36,
  OptionCode_TCPDefaultTTL = 37,
  OptionCode_TCPKeepaliveInterval = 38,
  OptionCode_TCPKeepaliveGarbage = 39,
  OptionCode_NetworkInformationServiceDomain = 40,
  OptionCode_NetworkInformationServers = 41,
  OptionCode_NTPServers = 42,
  OptionCode_VendorSpecificInformation = 43,
  OptionCode_NetBIOSOverTCPIPNameServer = 44,
  OptionCode_NetBIOSOverTCPIPDatagramDistributionServer = 45,
  OptionCode_NetBIOSOverTCPIPNodeType = 46,
  OptionCode_NetBIOSOverTCPIPScope = 47,
  OptionCode_XWindowSystemFontServer = 48,
  OptionCode_XWindowSystemDisplayManager = 49,
  OptionCode_RequestedIPAddress = 50,
  OptionCode_IPAddressLeaseTime = 51,
  OptionCode_Overload = 52,
  OptionCode_MessageType = 53,
  OptionCode_ServerIdentifier = 54,
  OptionCode_ParameterRequestList = 55,
  OptionCode_Message = 56,
  OptionCode_MaximumDHCPMessageSize = 57,
  OptionCode_RenewalTimeValue = 58,
  OptionCode_RebindingTimeValue = 59,
  OptionCode_VendorClassIdentifier = 60,
  OptionCode_ClientIdentifier = 61,
  OptionCode_NetworkInformationServicePlusDomain = 64,
  OptionCode_NetworkInformationServicePlusServers = 65,
  OptionCode_TFTPServerName = 66,
  OptionCode_BootfileName = 67,
  OptionCode_MobileIPHomeAgent = 68,
  OptionCode_SimpleMailTransportProtocol = 69,
  OptionCode_PostOfficeProtocolServer = 70,
  OptionCode_NetworkNewsTransportProtocol = 71,
  OptionCode_DefaultWorldWideWebServer = 72,
  OptionCode_DefaultFingerServer = 73,
  OptionCode_DefaultInternetRelayChatServer = 74,
  OptionCode_StreetTalkServer = 75,
  OptionCode_StreetTalkDirectoryAssistance = 76,
  OptionCode_DomainSearch = 119,
  OptionCode_ClasslessStaticRoute = 121,
  OptionCode_PrivateClasslessStaticRoute = 249,
  OptionCode_PrivateProxyAutoDiscovery = 252,
  OptionCode_End = 255,
};

string OptionCodeToString(OptionCode code) {
  switch (code) {
  case OptionCode_Pad:
    return "Pad";
  case OptionCode_SubnetMask:
    return "Subnet Mask";
  case OptionCode_TimeOffset:
    return "Time Offset";
  case OptionCode_Router:
    return "Router";
  case OptionCode_TimeServer:
    return "Time Server";
  case OptionCode_NameServer:
    return "Name Server";
  case OptionCode_DomainNameServer:
    return "Domain Name Server";
  case OptionCode_LogServer:
    return "Log Server";
  case OptionCode_CookieServer:
    return "Cookie Server";
  case OptionCode_LPRServer:
    return "LPR Server";
  case OptionCode_ImpressServer:
    return "Impress Server";
  case OptionCode_ResourceLocationServer:
    return "Resource Location Server";
  case OptionCode_HostName:
    return "Host Name";
  case OptionCode_BootFileSize:
    return "Boot File Size";
  case OptionCode_MeritDumpFile:
    return "Merit Dump File";
  case OptionCode_DomainName:
    return "Domain Name";
  case OptionCode_SwapServer:
    return "Swap Server";
  case OptionCode_RootPath:
    return "Root Path";
  case OptionCode_ExtensionsPath:
    return "Extensions Path";
  case OptionCode_IPForwarding:
    return "IP Forwarding Enable/Disable";
  case OptionCode_NonLocalSourceRouting:
    return "Non-Local Source Routing Enable/Disable";
  case OptionCode_PolicyFilter:
    return "Policy Filter";
  case OptionCode_MaximumDatagramReassemblySize:
    return "Maximum Datagram Reassembly Size";
  case OptionCode_DefaultIPTimeToLive:
    return "Default IP Time To Live";
  case OptionCode_PathMTUAgingTimeout:
    return "Path MTU Aging Timeout";
  case OptionCode_PathMTUPlateauTable:
    return "Path MTU Plateau Table";
  case OptionCode_InterfaceMTU:
    return "Interface MTU";
  case OptionCode_AllSubnetsAreLocal:
    return "All Subnets Are Local";
  case OptionCode_BroadcastAddress:
    return "Broadcast Address";
  case OptionCode_PerformMaskDiscovery:
    return "Perform Mask Discovery";
  case OptionCode_MaskSupplier:
    return "Mask Supplier";
  case OptionCode_PerformRouterDiscovery:
    return "Perform Router Discovery";
  case OptionCode_RouterSolicitationAddress:
    return "Router Solicitation Address";
  case OptionCode_StaticRoute:
    return "Static Route";
  case OptionCode_TrailerEncapsulation:
    return "Trailer Encapsulation";
  case OptionCode_ARPCacheTimeout:
    return "ARP Cache Timeout";
  case OptionCode_EthernetEncapsulation:
    return "Ethernet Encapsulation";
  case OptionCode_TCPDefaultTTL:
    return "TCP Default TTL";
  case OptionCode_TCPKeepaliveInterval:
    return "TCP Keepalive Interval";
  case OptionCode_TCPKeepaliveGarbage:
    return "TCP Keepalive Garbage";
  case OptionCode_NetworkInformationServiceDomain:
    return "Network Information Service Domain";
  case OptionCode_NetworkInformationServers:
    return "Network Information Servers";
  case OptionCode_NTPServers:
    return "NTP Servers";
  case OptionCode_VendorSpecificInformation:
    return "Vendor Specific Information";
  case OptionCode_NetBIOSOverTCPIPNameServer:
    return "NetBIOS over TCP/IP Name Server";
  case OptionCode_NetBIOSOverTCPIPDatagramDistributionServer:
    return "NetBIOS over TCP/IP Datagram Distribution Server";
  case OptionCode_NetBIOSOverTCPIPNodeType:
    return "NetBIOS over TCP/IP Node Type";
  case OptionCode_NetBIOSOverTCPIPScope:
    return "NetBIOS over TCP/IP Scope";
  case OptionCode_XWindowSystemFontServer:
    return "X Window System Font Server";
  case OptionCode_XWindowSystemDisplayManager:
    return "X Window System Display Manager";
  case OptionCode_RequestedIPAddress:
    return "Requested IP Address";
  case OptionCode_IPAddressLeaseTime:
    return "IP Address Lease Time";
  case OptionCode_Overload:
    return "Overload";
  case OptionCode_MessageType:
    return "Message Type";
  case OptionCode_ServerIdentifier:
    return "Server Identifier";
  case OptionCode_ParameterRequestList:
    return "Parameter Request List";
  case OptionCode_Message:
    return "Message";
  case OptionCode_MaximumDHCPMessageSize:
    return "Maximum DHCP Message Size";
  case OptionCode_RenewalTimeValue:
    return "Renewal (T1) Time Value";
  case OptionCode_RebindingTimeValue:
    return "Rebinding (T2) Time Value";
  case OptionCode_VendorClassIdentifier:
    return "Vendor Class Identifier";
  case OptionCode_ClientIdentifier:
    return "Client Identifier";
  case OptionCode_NetworkInformationServicePlusDomain:
    return "Network Information Service+ Domain";
  case OptionCode_NetworkInformationServicePlusServers:
    return "Network Information Service+ Servers";
  case OptionCode_TFTPServerName:
    return "TFTP Server Name";
  case OptionCode_BootfileName:
    return "Bootfile Name";
  case OptionCode_MobileIPHomeAgent:
    return "Mobile IP Home Agent";
  case OptionCode_SimpleMailTransportProtocol:
    return "Simple Mail Transport Protocol";
  case OptionCode_PostOfficeProtocolServer:
    return "Post Office Protocol Server";
  case OptionCode_NetworkNewsTransportProtocol:
    return "Network News Transport Protocol";
  case OptionCode_DefaultWorldWideWebServer:
    return "Default World Wide Web Server";
  case OptionCode_DefaultFingerServer:
    return "Default Finger Server";
  case OptionCode_DefaultInternetRelayChatServer:
    return "Default Internet Relay Chat Server";
  case OptionCode_StreetTalkServer:
    return "StreetTalk Server";
  case OptionCode_StreetTalkDirectoryAssistance:
    return "StreetTalk Directory Assistance";
  case OptionCode_DomainSearch:
    return "Domain Search";
  case OptionCode_ClasslessStaticRoute:
    return "Classless Static Route";
  case OptionCode_PrivateClasslessStaticRoute:
    return "Private/Classless Static Route (Microsoft)";
  case OptionCode_PrivateProxyAutoDiscovery:
    return "Private/Proxy autodiscovery";
  case OptionCode_End:
    return "End";
  default:
    return "Unknown option code " + std::to_string(code);
  }
}

struct __attribute__((__packed__)) Base {
  OptionCode code;
  uint8_t length;
  Base(OptionCode code, uint8_t length = 0) : code(code), length(length) {}
  string to_string() const;
  size_t size() const {
    switch (code) {
    case 0:
    case 255:
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
  SubnetMask(const IP &ip) : Base(OptionCode_SubnetMask, 4), ip(ip) {}
  string to_string() const { return "SubnetMask(" + ip.to_string() + ")"; }
};

static_assert(sizeof(SubnetMask) == 6, "SubnetMask is not packed correctly");

struct __attribute__((__packed__)) Router : Base {
  const IP ip;
  Router(const IP &ip) : Base(OptionCode_Router, 4), ip(ip) {}
  string to_string() const { return "Router(" + ip.to_string() + ")"; }
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
  string to_string() const {
    int n = length / 4;
    string r = "DomainNameServer(";
    for (int i = 0; i < n; ++i) {
      if (i > 0) {
        r += ", ";
      }
      r += dns[i].to_string();
    }
    r += ")";
    return r;
  }

private:
  DomainNameServer(int dns_count)
      : Base(OptionCode_DomainNameServer, 4 * dns_count) {}
};

struct __attribute__((__packed__)) HostName : Base {
  static constexpr OptionCode kCode = OptionCode_HostName;
  const uint8_t value[];
  HostName() = delete;
  string to_string() const { return "HostName(" + hostname() + ")"; }
  string hostname() const { return std::string((const char *)value, length); }
};

struct __attribute__((__packed__)) DomainName : Base {
  static constexpr OptionCode kCode = OptionCode_DomainName;
  const uint8_t value[];
  static unique_ptr<DomainName, FreeDeleter> Make(string domain_name) {
    int n = domain_name.size();
    void *buffer = malloc(sizeof(DomainName) + n);
    auto r = unique_ptr<DomainName, FreeDeleter>(new (buffer) DomainName(n));
    memcpy((void *)r->value, domain_name.data(), n);
    return r;
  }
  string domain_name() const {
    return std::string((const char *)value, length);
  }
  string to_string() const { return "DomainName(" + domain_name() + ")"; }

private:
  DomainName(int length) : Base(kCode, length) {}
};

struct __attribute__((__packed__)) RequestedIPAddress : Base {
  static constexpr OptionCode kCode = OptionCode_RequestedIPAddress;
  const IP ip;
  RequestedIPAddress(const IP &ip) : Base(kCode, 4), ip(ip) {}
  string to_string() const {
    return "RequestedIPAddress(" + ip.to_string() + ")";
  }
};

struct __attribute__((__packed__)) IPAddressLeaseTime : Base {
  const uint32_t seconds;
  IPAddressLeaseTime(uint32_t seconds)
      : Base(OptionCode_IPAddressLeaseTime, 4), seconds(htonl(seconds)) {}
  string to_string() const {
    return "IPAddressLeaseTime(" + std::to_string(ntohl(seconds)) + ")";
  }
};

struct __attribute__((__packed__)) MessageType : Base {
  enum Value : uint8_t {
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
  static const char *kValueNames[VALUE_COUNT];
  static string ValueToString(Value value) {
    if (value < VALUE_COUNT) {
      return kValueNames[value];
    }
    return f("UNKNOWN(%d)", value);
  }
  const Value value;
  MessageType(Value value) : Base(OptionCode_MessageType, 1), value(value) {}
  string to_string() const {
    return "MessageType(" + ValueToString(value) + ")";
  }
};

const char *MessageType::kValueNames[VALUE_COUNT] = {"UNKNOWN",
                                                     "DISCOVER",
                                                     "OFFER",
                                                     "REQUEST",
                                                     "DECLINE",
                                                     "ACK",
                                                     "NAK",
                                                     "RELEASE",
                                                     "INFORM",
                                                     "FORCERENEW",
                                                     "LEASEQUERY",
                                                     "LEASEUNASSIGNED",
                                                     "LEASEUNKNOWN",
                                                     "LEASEACTIVE",
                                                     "BULKLEASEQUERY",
                                                     "LEASEQUERYDONE",
                                                     "ACTIVELEASEQUERY",
                                                     "LEASEQUERYSTATUS",
                                                     "TLS"};

struct __attribute__((__packed__)) ServerIdentifier : Base {
  const IP ip;
  ServerIdentifier(const IP &ip)
      : Base(OptionCode_ServerIdentifier, 4), ip(ip) {}
  string to_string() const {
    return "ServerIdentifier(" + ip.to_string() + ")";
  }
};

// RFC 2132, section 9.8
struct __attribute__((__packed__)) ParameterRequestList {
  const uint8_t code = 55;
  const uint8_t length;
  const OptionCode c[0];
  string to_string() const {
    string r = "ParameterRequestList(";
    for (int i = 0; i < length; ++i) {
      r += "\n  ";
      r += OptionCodeToString(c[i]);
    }
    r += ")";
    return r;
  }
};

// RFC 2132, section 9.10
struct __attribute__((__packed__)) MaximumDHCPMessageSize {
  const uint8_t code = 57;
  const uint8_t length = 2;
  const uint16_t value = htons(1500);
  string to_string() const {
    return "MaximumDHCPMessageSize(" + std::to_string(ntohs(value)) + ")";
  }
};

struct __attribute__((__packed__)) VendorClassIdentifier {
  const uint8_t code = 60;
  const uint8_t length;
  const uint8_t value[0];
  string to_string() const {
    return "VendorClassIdentifier(" + std::string((const char *)value, length) +
           ")";
  }
};

// RFC 2132, Section 9.14
struct __attribute__((__packed__)) ClientIdentifier : Base {
  static constexpr OptionCode kCode = OptionCode_ClientIdentifier;
  const uint8_t type = 1; // Hardware address
  const MAC hardware_address;
  ClientIdentifier(const MAC &hardware_address)
      : Base(kCode, 1 + 6), hardware_address(hardware_address) {}
  string to_string() const {
    string r = "ClientIdentifier(";
    r += rfc1700::HardwareTypeToString(type);
    r += ", " + hardware_address.to_string() + ")";
    return r;
  }
};

struct __attribute__((__packed__)) End : Base {
  End() : Base(OptionCode_End) {}
};

string Base::to_string() const {
  switch (code) {
  case OptionCode_SubnetMask:
    return ((const options::SubnetMask *)this)->to_string();
  case OptionCode_Router:
    return ((const options::Router *)this)->to_string();
  case OptionCode_DomainNameServer:
    return ((const options::DomainNameServer *)this)->to_string();
  case OptionCode_HostName:
    return ((const options::HostName *)this)->to_string();
  case OptionCode_DomainName:
    return ((const options::DomainName *)this)->to_string();
  case OptionCode_RequestedIPAddress:
    return ((const options::RequestedIPAddress *)this)->to_string();
  case OptionCode_IPAddressLeaseTime:
    return ((const options::IPAddressLeaseTime *)this)->to_string();
  case OptionCode_MessageType:
    return ((const options::MessageType *)this)->to_string();
  case OptionCode_ServerIdentifier:
    return ((const options::ServerIdentifier *)this)->to_string();
  case OptionCode_ParameterRequestList:
    return ((const options::ParameterRequestList *)this)->to_string();
  case OptionCode_MaximumDHCPMessageSize:
    return ((const options::MaximumDHCPMessageSize *)this)->to_string();
  case OptionCode_VendorClassIdentifier:
    return ((const options::VendorClassIdentifier *)this)->to_string();
  case OptionCode_ClientIdentifier:
    return ((const options::ClientIdentifier *)this)->to_string();
  default:
    const char *data = (const char *)(this) + sizeof(*this);
    return "\"" + OptionCodeToString(code) + "\" " + std::to_string(length) +
           " bytes: " + BytesToHex(Span<>(data, length));
  }
}

} // namespace options

// Fixed prefix of a DHCP packet. This is followed by a list of options.
// All fields use network byte order.
struct __attribute__((__packed__)) Header {
  uint8_t message_type = 1;  // Boot Request
  uint8_t hardware_type = 1; // Ethernet
  uint8_t hardware_address_length = 6;
  uint8_t hops = 0;
  uint32_t transaction_id = random<uint32_t>();
  uint16_t seconds_elapsed = 0;
  uint16_t flags = 0;
  IP client_ip = {0, 0, 0, 0};  // ciaddr
  IP your_ip = {0, 0, 0, 0};    // yiaddr
  IP server_ip = {0, 0, 0, 0};  // siaddr (Next server IP)
  IP gateway_ip = {0, 0, 0, 0}; // giaddr (Relay agent IP)
  union {
    uint8_t client_hardware_address[16] = {};
    MAC client_mac_address;
  };
  uint8_t server_name[64] = {};
  uint8_t boot_filename[128] = {};
  uint32_t magic_cookie = htonl(kMagicCookie);

  string to_string() const {
    string s = "dhcp::Header {\n";
    s += "  message_type: " + std::to_string(message_type) + "\n";
    s += "  hardware_type: " + rfc1700::HardwareTypeToString(hardware_type) +
         "\n";
    s += "  hardware_address_length: " +
         std::to_string(hardware_address_length) + "\n";
    s += "  hops: " + std::to_string(hops) + "\n";
    s += "  transaction_id: " + ValToHex(transaction_id) + "\n";
    s += "  seconds_elapsed: " + std::to_string(seconds_elapsed) + "\n";
    s += "  flags: " + std::to_string(ntohs(flags)) + "\n";
    s += "  client_ip: " + client_ip.to_string() + "\n";
    s += "  your_ip: " + your_ip.to_string() + "\n";
    s += "  server_ip: " + server_ip.to_string() + "\n";
    s += "  gateway_ip: " + gateway_ip.to_string() + "\n";
    s += "  client_mac_address: " + client_mac_address.to_string() + "\n";
    s += "  server_name: " + std::string((const char *)server_name) + "\n";
    s += "  boot_filename: " + std::string((const char *)boot_filename) + "\n";
    s += "  magic_cookie: " + ValToHex(magic_cookie) + "\n";
    s += "}";
    return s;
  }

  void write_to(string &buffer) {
    buffer.append((const char *)this, sizeof(*this));
  }
};

// Provides read access to a memory buffer that contains a DHCP packet.
struct __attribute__((__packed__)) PacketView : Header {
  uint8_t options[0];
  void CheckFitsIn(size_t len, string &error) {
    if (len < sizeof(Header)) {
      error = "Packet is too short";
      return;
    }
    if (len < sizeof(Header) + 1) {
      error = "Packet is too short to contain an End option";
      return;
    }
    uint8_t *p = options;
    while (true) {
      options::Base *opt = (options::Base *)p;
      p += opt->size();
      if (opt->code == options::OptionCode_End) {
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
  string to_string() const {
    string s = "dhcp::PacketView {\n";
    s += IndentString(Header::to_string());
    s += "\n  options:\n";
    const uint8_t *p = options;
    while (*p != 255) {
      const options::Base &opt = *(const options::Base *)p;
      s += IndentString(opt.to_string(), 4) + "\n";
      p += opt.size();
    }
    s += "}";
    return s;
  }
  options::Base *FindOption(options::OptionCode code) const {
    const uint8_t *p = options;
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
            options::OptionCode_MessageType)) {
      return o->value;
    }
    return options::MessageType::UNKNOWN;
  }
  string client_id() const {
    if (auto *opt = FindOption<options::ClientIdentifier>()) {
      return opt->hardware_address.to_string();
    }
    return client_mac_address.to_string();
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
  string client_id = request.client_id();
  // Try to find entry with matching client_id.
  for (auto it : server.entries) {
    const Server::Entry &entry = it.second;
    if (entry.client_id == client_id) {
      return it.first;
    }
  }
  // Take the requested IP if it is available.
  if (auto *opt = request.FindOption<options::RequestedIPAddress>()) {
    const IP requested_ip = opt->ip;
    bool ok = IsValidClientIP(requested_ip);
    if (!ok) {
      ok = false;
    }
    if (auto it = server.entries.find(requested_ip);
        it != server.entries.end()) {
      Server::Entry &entry = it->second;
      if ((entry.client_id != client_id) &&
          (entry.expiration ? entry.expiration > steady_clock::now() : true)) {
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
    if (auto it = server.entries.find(ip); it == server.entries.end()) {
      return ip;
    }
  }
  // Try to find the most expired IP.
  IP oldest_ip(0, 0, 0, 0);
  steady_clock::time_point oldest_expiration = steady_clock::time_point::max();
  for (auto it : server.entries) {
    const Server::Entry &entry = it.second;
    if (entry.expiration && *entry.expiration < oldest_expiration) {
      oldest_ip = it.first;
      oldest_expiration = *entry.expiration;
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

void Server::Init() {
  for (auto [mac, ip] : etc::ethers) {
    auto &entry = entries[ip];
    entry.client_id = mac.to_string();
    entry.stable = true;
    if (auto etc_hosts_it = etc::hosts.find(ip);
        etc_hosts_it != etc::hosts.end()) {
      auto &aliases = etc_hosts_it->second;
      if (!aliases.empty()) {
        entry.hostname = aliases[0];
      }
    }
  }
}
int AvailableIPs(const Server &server) {
  int zeros = lan_network.Zeros();
  // 3 IPs are reserved: network, broadcast, and server.
  return (1 << zeros) - server.entries.size() - 3;
}
void Server::Listen(Status &status) {
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

void Server::StopListening() {
  Status ignored;
  epoll::Del(this, ignored);
  shutdown(fd, SHUT_RDWR);
  close(fd);
}

void Server::HandleRequest(string_view buf, IP source_ip, uint16_t port) {
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
  if (ntohl(packet.magic_cookie) != kMagicCookie) {
    ERROR << "DHCP server received a packet with an invalid magic cookie: "
          << ValToHex(packet.magic_cookie);
    return;
  }
  if ((packet.server_ip <=> lan_ip != 0) &&
      (packet.server_ip <=> IP(0, 0, 0, 0) != 0)) {
    // Silently ignore packets that are not for us.
    return;
  }

  options::MessageType::Value response_type = options::MessageType::UNKNOWN;
  steady_clock::duration lease_time = 0s;
  bool inform = false;

  const IP chosen_ip =
      inform ? IP(0, 0, 0, 0) : ChooseIP(*this, packet, log_error);
  if (!log_error.empty()) {
    ERROR << log_error << "\n" << packet.to_string();
    return;
  }

  int request_lease_time_seconds = 60;
  switch (packet.MessageType()) {
  case options::MessageType::DISCOVER:
    response_type = options::MessageType::OFFER;
    lease_time = 10s;
    break;
  case options::MessageType::REQUEST:
    if (auto *opt = packet.FindOption<options::RequestedIPAddress>();
        opt != nullptr && opt->ip != chosen_ip) {
      response_type = options::MessageType::NAK;
    } else {
      response_type = options::MessageType::ACK;
    }
    lease_time = request_lease_time_seconds * 1s;
    break;
  case options::MessageType::INFORM:
    response_type = options::MessageType::ACK;
    lease_time = 0s;
    inform = true;
    break;
  case options::MessageType::RELEASE:
    if (auto it = entries.find(packet.client_ip);
        it != entries.end() && it->second.client_id == packet.client_id()) {
      entries.erase(it);
    }
    return;
  default:
    response_type = options::MessageType::UNKNOWN;
    break;
  }

  if (inform && source_ip != packet.client_ip && source_ip != IP(0, 0, 0, 0)) {
    ERROR << "DHCP server received an INFORM packet with a mismatching "
             "source IP: "
          << source_ip.to_string() << " (source IP) vs "
          << packet.client_ip.to_string() << " (DHCP client_ip)"
          << "\n"
          << packet.to_string();
    return;
  }

  IP response_ip = inform ? packet.client_ip : chosen_ip;
  if (!IsValidClientIP(response_ip)) {
    ERROR << "DHCP server received a packet with an invalid response IP: "
          << response_ip.to_string() << "\n"
          << packet.to_string();
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

  if (response_type == options::MessageType::UNKNOWN) {
    LOG << "DHCP server received unknown DHCP message:\n" << packet.to_string();
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
    auto &entry = entries[chosen_ip];
    entry.client_id = packet.client_id();
    entry.last_request = steady_clock::now();
    entry.expiration = steady_clock::now() + lease_time;
    if (auto opt = packet.FindOption<options::HostName>()) {
      entry.hostname = opt->hostname();
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
    out = f("%d", server.entries.size());
    break;
  case 1:
    out = f("%d", AvailableIPs(server));
    break;
  }
}
std::string Table::RowID(int row) const { return "dhcp-onlyrow"; }

} // namespace dhcp