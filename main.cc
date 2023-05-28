// Gatekeeper is a combined DHCP server & DNS proxy for home networks. It's
// designed to run on the gateway router of a home network. It's web interface
// allows the user to easily inspect the state of the network: see what devices
// are connected and snoop on DNS requests by IoT devices.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <initializer_list>
#include <limits>
#include <map>
#include <optional>
#include <queue>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "epoll.hh"
#include "format.hh"
#include "hex.hh"
#include "http.hh"
#include "ip.hh"
#include "log.hh"
#include "mac.hh"
#include "random.hh"

using namespace std;
using chrono::steady_clock;

const string kLocalDomain = "local";

// Default values will be overwritten during startup.
// Those values could actually be fetched from the kernel each time they're
// needed. This might be useful if the network configuration changes while the
// program is running. If this ever becomes a problem, just remove those
// variables.
string interface_name = "eth0";
IP server_ip = {192, 168, 1, 1};
IP netmask = {255, 255, 255, 0};

// Prefix each line with `spaces` spaces.
std::string IndentString(std::string in, int spaces = 2) {
  std::string out(spaces, ' ');
  for (char c : in) {
    out += c;
    if (c == '\n') {
      for (int i = 0; i < spaces; ++i) {
        out += ' ';
      }
    }
  }
  return out;
}

string FormatDuration(optional<steady_clock::duration> d_opt,
                      const char *never = "∞") {
  if (!d_opt) {
    return never;
  }
  steady_clock::duration &d = *d_opt;
  string r;
  auto h = duration_cast<chrono::hours>(d);
  d -= h;
  if (h.count() > 0) {
    r += std::to_string(h.count()) + "h";
  }
  auto m = duration_cast<chrono::minutes>(d);
  d -= m;
  if (m.count() > 0) {
    if (!r.empty()) {
      r += " ";
    }
    r += std::to_string(m.count()) + "m";
  }
  auto s = duration_cast<chrono::seconds>(d);
  d -= s;
  if (r.empty() || (s.count() > 0)) {
    if (!r.empty()) {
      r += " ";
    }
    r += std::to_string(s.count()) + "s";
  }
  return r;
}

void SetNonBlocking(int fd, string &error) {
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0) {
    error = "fcntl(F_GETFL) failed: ";
    error += strerror(errno);
    return;
  }

  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    error = "fcntl(F_SETFL) failed: ";
    error += strerror(errno);
    return;
  }
}

void SendTo(int fd, const string &buffer, IP ip, uint16_t port, string &error) {
  sockaddr_in dest_addr = {
      .sin_family = AF_INET,
      .sin_port = htons(port),
      .sin_addr = {.s_addr = ip.addr},
  };
  if (sendto(fd, buffer.data(), buffer.size(), 0, (struct sockaddr *)&dest_addr,
             sizeof(dest_addr)) < 0) {
    error = "sendto: " + string(strerror(errno));
  }
}

struct UDPListener : epoll::Listener {
  virtual void HandleRequest(string_view buf, IP source_ip,
                             uint16_t source_port) = 0;

  void NotifyRead(string &abort_error) override {
    while (true) {
      sockaddr_in clientaddr;
      socklen_t clilen = sizeof(struct sockaddr);
      ssize_t len = recvfrom(fd, recvbuf, sizeof(recvbuf), 0,
                             (struct sockaddr *)&clientaddr, &clilen);
      if (len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          break;
        } else {
          abort_error = "DNS server recvfrom: ";
          abort_error += strerror(errno);
          return;
        }
      }
      IP source_ip(clientaddr.sin_addr.s_addr);
      uint16_t source_port = ntohs(clientaddr.sin_port);
      HandleRequest(string_view((char *)recvbuf, len), source_ip, source_port);
    }
  }

private:
  uint8_t recvbuf[65536] = {0};
};

template <class... Ts> struct overloaded : Ts... {
  using Ts::operator()...;
};
// explicit deduction guide (not needed as of C++20)
template <class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

template <typename Iter> Iter next(Iter iter) { return ++iter; }

namespace log_ {
deque<string> messages;

void Log(string_view message) {
  messages.emplace_back(message);
  while (messages.size() > 20) {
    messages.pop_front();
  }
}
} // namespace log_

namespace rfc1700 {

const char *kHardwareTypeNames[] = {"Not hardware address",
                                    "Ethernet (10Mb)",
                                    "Experimental Ethernet (3Mb)",
                                    "Amateur Radio AX.25",
                                    "Proteon ProNET Token Ring",
                                    "Chaos",
                                    "IEEE 802 Networks",
                                    "ARCNET",
                                    "Hyperchannel",
                                    "Lanstar",
                                    "Autonet Short Address",
                                    "LocalTalk",
                                    "LocalNet (IBM PCNet or SYTEK LocalNET)",
                                    "Ultra link",
                                    "SMDS",
                                    "Frame Relay",
                                    "Asynchronous Transmission Mode (ATM)",
                                    "HDLC",
                                    "Fibre Channel",
                                    "Asynchronous Transmission Mode (ATM)",
                                    "Serial Line",
                                    "Asynchronous Transmission Mode (ATM)"};

string HardwareTypeToString(uint8_t type) {
  if (type < sizeof(kHardwareTypeNames) / sizeof(kHardwareTypeNames[0])) {
    return kHardwareTypeNames[type];
  }
  return "Unknown hardware type " + std::to_string(type);
}

} // namespace rfc1700

namespace arp {

struct IOCtlRequest {
  struct sockaddr_in protocol_address;
  struct sockaddr hardware_address;
  int flags;
  struct sockaddr netmask; /* Only for proxy arps.  */
  char device[16];
};

static_assert(sizeof(IOCtlRequest) == sizeof(arpreq),
              "IOCtlRequest doesn't match `struct arpreq` from <net/if_arp.h>");

void Set(IP ip, MAC mac, int af_inet_fd, string &error) {
  IOCtlRequest r{
      .protocol_address = {.sin_family = AF_INET,
                           .sin_addr = {.s_addr = ip.addr}},
      .hardware_address = {.sa_family = AF_UNSPEC,
                           .sa_data = {(char)mac[0], (char)mac[1], (char)mac[2],
                                       (char)mac[3], (char)mac[4],
                                       (char)mac[5]}},
      .flags = ATF_COM,
  };
  strncpy(r.device, interface_name.c_str(), sizeof(r.device));
  if (ioctl(af_inet_fd, SIOCSARP, &r) < 0) {
    error = "ioctl(SIOCSARP) failed: " + string(strerror(errno));
  }
}

} // namespace arp

namespace etc {

map<IP, vector<string>> ReadHosts() {
  map<IP, vector<string>> etc_hosts;
  std::ifstream hosts_stream("/etc/hosts");
  std::string line;
  while (std::getline(hosts_stream, line)) {
    if (auto pos = line.find("#"); pos != string::npos) {
      line.resize(pos);
    }
    std::istringstream iss(line);
    std::string ip_str;
    if (!(iss >> ip_str)) {
      continue;
    }
    IP ip;
    if (!ip.TryParse(ip_str.c_str())) {
      continue;
    }
    std::string hostname;
    while (iss >> hostname) {
      etc_hosts[ip].push_back(hostname);
    }
  }
  return etc_hosts;
}

map<MAC, IP> ReadEthers(const map<IP, vector<string>> &etc_hosts) {
  map<MAC, IP> etc_ethers;
  ifstream ethers_stream("/etc/ethers");
  string line;
  while (getline(ethers_stream, line)) {
    if (auto pos = line.find("#"); pos != string::npos) {
      line.resize(pos);
    }
    istringstream iss(line);
    string mac_str;
    string addr_str;
    if (!(iss >> mac_str >> addr_str)) {
      continue;
    }
    MAC mac;
    if (!mac.TryParse(mac_str.c_str())) {
      continue;
    }
    IP ip;
    if (ip.TryParse(addr_str.c_str())) {
      etc_ethers[mac] = ip;
    } else {
      for (auto it : etc_hosts) {
        for (auto hostname : it.second) {
          if (hostname == addr_str) {
            etc_ethers[mac] = it.first;
            goto outer;
          }
        }
      }
    outer:
    }
  }
  return etc_ethers;
}

vector<IP> ReadResolv() {
  vector<IP> resolv;
  ifstream resolv_stream("/etc/resolv.conf");
  string line;
  while (getline(resolv_stream, line)) {
    if (auto pos = line.find("#"); pos != string::npos) {
      line.resize(pos);
    }
    istringstream iss(line);
    string keyword;
    if (!(iss >> keyword)) {
      continue;
    }
    if (keyword == "nameserver") {
      string ip_str;
      if (iss >> ip_str) {
        IP ip;
        if (ip.TryParse(ip_str.c_str())) {
          resolv.push_back(ip);
        }
      }
    }
  }
  return resolv;
}

string ReadHostname() {
  ifstream hostname_stream("/etc/hostname");
  string hostname;
  getline(hostname_stream, hostname);
  return hostname;
}

map<IP, vector<string>> hosts;
map<MAC, IP> ethers;
vector<IP> resolv = {IP(8, 8, 8, 8), IP(8, 8, 4, 4)};
string hostname = "localhost";

// Read files from /etc/ and populate etc::hosts & etc::ethers.
void ReadConfig() {
  hosts = ReadHosts();
  ethers = ReadEthers(hosts);
  resolv = ReadResolv();
  hostname = ReadHostname();
}

} // namespace etc

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
  static unique_ptr<DomainNameServer> Make(initializer_list<IP> ips) {
    int n = ips.size();
    void *buffer = malloc(sizeof(DomainNameServer) + sizeof(IP) * n);
    auto r = unique_ptr<DomainNameServer>(new (buffer) DomainNameServer(n));
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
  const uint8_t value[0];
  HostName() = delete;
  string to_string() const { return "HostName(" + hostname() + ")"; }
  string hostname() const { return std::string((const char *)value, length); }
};

struct __attribute__((__packed__)) DomainName : Base {
  static constexpr OptionCode kCode = OptionCode_DomainName;
  const uint8_t value[0];
  static unique_ptr<DomainName> Make(string domain_name) {
    int n = domain_name.size();
    void *buffer = malloc(sizeof(DomainName) + n);
    auto r = unique_ptr<DomainName>(new (buffer) DomainName(n));
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
    const uint8_t *data = (const uint8_t *)(this) + sizeof(*this);
    return "\"" + OptionCodeToString(code) + "\" " + std::to_string(length) +
           " bytes: " + hex(data, length);
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
    s += "  transaction_id: " + hex(&transaction_id, sizeof(transaction_id)) +
         "\n";
    s += "  seconds_elapsed: " + std::to_string(seconds_elapsed) + "\n";
    s += "  flags: " + std::to_string(ntohs(flags)) + "\n";
    s += "  client_ip: " + client_ip.to_string() + "\n";
    s += "  your_ip: " + your_ip.to_string() + "\n";
    s += "  server_ip: " + server_ip.to_string() + "\n";
    s += "  gateway_ip: " + gateway_ip.to_string() + "\n";
    s += "  client_mac_address: " + client_mac_address.to_string() + "\n";
    s += "  server_name: " + std::string((const char *)server_name) + "\n";
    s += "  boot_filename: " + std::string((const char *)boot_filename) + "\n";
    s += "  magic_cookie: " + hex(&magic_cookie, sizeof(magic_cookie)) + "\n";
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
      opt->hardware_address.to_string();
    }
    return client_mac_address.to_string();
  }
};

struct Server : UDPListener {

  struct Entry {
    string client_id;
    string hostname;
    optional<steady_clock::time_point> expiration;
    bool stable = false;
    optional<steady_clock::time_point> last_request;
  };

  map<IP, Entry> entries;

  void Init() {
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

  // Start listening.
  //
  // To actually accept new connections, make sure to Poll the `epoll`
  // instance after listening.
  void Listen(string &error) {
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
      error = "socket";
      return;
    }

    SetNonBlocking(fd, error);
    if (!error.empty()) {
      StopListening();
      return;
    }

    int flag = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag)) <
        0) {
      error = "setsockopt: SO_REUSEADDR";
      StopListening();
      return;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface_name.data(),
                   interface_name.size()) < 0) {
      error = "Error when setsockopt bind to device";
      StopListening();
      return;
    };

    sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(kServerPort),
        .sin_addr = {.s_addr = htonl(INADDR_ANY)},
    };

    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
      error = "bind: ";
      error += strerror(errno);
      StopListening();
      return;
    }

    epoll::Add(this, error);
  }

  // Stop listening.
  void StopListening() {
    string error_ignored;
    epoll::Del(this, error_ignored);
    shutdown(fd, SHUT_RDWR);
    close(fd);
  }

  void SendTo(const string &buffer, IP ip, string &error) {
    ::SendTo(fd, buffer, ip, kClientPort, error);
  }

  // Function used to validate IP addresses provided by clients.
  bool IsValidClientIP(IP requested_ip) {
    const IP network_ip = server_ip & netmask;
    const IP broadcast_ip = network_ip | ~netmask;
    if (network_ip != (requested_ip & netmask)) {
      // Requested IP outside of our network.
      return false;
    }
    if (requested_ip == network_ip) {
      // Requested IP is the network address.
      return false;
    }
    if (requested_ip == broadcast_ip) {
      // Requested IP is the broadcast address.
      return false;
    }
    if (requested_ip == server_ip) {
      // Requested IP is our own IP.
      return false;
    }
    return true;
  }

  IP ChooseIP(const PacketView &request, string &error) {
    const IP network_ip = server_ip & netmask;
    const IP broadcast_ip = network_ip | ~netmask;
    string client_id = request.client_id();
    // Try to find entry with matching client_id.
    for (auto it : entries) {
      const Entry &entry = it.second;
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
      if (auto it = entries.find(requested_ip); it != entries.end()) {
        Entry &entry = it->second;
        if ((entry.client_id != client_id) &&
            (entry.expiration ? entry.expiration > steady_clock::now()
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
    for (IP ip = network_ip + 1; ip < broadcast_ip; ++ip) {
      if (ip == server_ip) {
        continue;
      }
      if (auto it = entries.find(ip); it == entries.end()) {
        return ip;
      }
    }
    // Try to find the most expired IP.
    IP oldest_ip(0, 0, 0, 0);
    steady_clock::time_point oldest_expiration =
        steady_clock::time_point::max();
    for (auto it : entries) {
      const Entry &entry = it.second;
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

  void HandleRequest(string_view buf, IP source_ip, uint16_t port) override {
    if (buf.size() < sizeof(PacketView)) {
      ERROR << "DHCP server received a packet that is too short: " << buf.size()
            << " bytes:\n"
            << hex(buf.data(), buf.size());
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
            << hex(&packet.magic_cookie, sizeof(packet.magic_cookie));
      return;
    }
    if ((packet.server_ip <=> server_ip != 0) &&
        (packet.server_ip <=> IP(0, 0, 0, 0) != 0)) {
      // Silently ignore packets that are not for us.
      return;
    }

    options::MessageType::Value response_type = options::MessageType::UNKNOWN;
    steady_clock::duration lease_time = 0s;
    bool inform = false;

    const IP chosen_ip = inform ? IP(0, 0, 0, 0) : ChooseIP(packet, log_error);
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
    default:
      response_type = options::MessageType::UNKNOWN;
      break;
    }

    if (inform && source_ip != packet.client_ip) {
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
      arp::Set(response_ip, packet.client_mac_address, fd, log_error);
      if (!log_error.empty()) {
        ERROR << "Failed to set the client IP/MAC association in the system "
                 "ARP table: "
              << log_error;
        return;
      }
    }

    if (response_type == options::MessageType::UNKNOWN) {
      log_::Log("DHCP server received unknown DHCP message:\n" +
                packet.to_string());
      return;
    }

    // Build response
    string buffer;
    Header{.message_type = 2, // Boot Reply
           .transaction_id = packet.transaction_id,
           .your_ip = chosen_ip,
           .server_ip = server_ip,
           .client_mac_address = packet.client_mac_address}
        .write_to(buffer);

    options::MessageType(response_type).write_to(buffer);
    options::SubnetMask(netmask).write_to(buffer);
    options::Router(server_ip).write_to(buffer);
    if (lease_time > 0s) {
      options::IPAddressLeaseTime(request_lease_time_seconds).write_to(buffer);
    }
    options::DomainName::Make(kLocalDomain)->write_to(buffer);
    options::ServerIdentifier(server_ip).write_to(buffer);
    options::DomainNameServer::Make({server_ip})->write_to(buffer);
    options::End().write_to(buffer);

    SendTo(buffer, response_ip, log_error);
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

  const char *Name() const override { return "dhcp::Server"; }
};

Server server;

} // namespace dhcp

namespace dns {

static constexpr uint16_t kServerPort = 53;
static constexpr steady_clock::duration kAuthoritativeTTL = 60s;

#define BIG_ENDIAN_16(x) ((x >> 8) | (x << 8))

enum class Type : uint16_t {
  A = BIG_ENDIAN_16(1),
  NS = BIG_ENDIAN_16(2),
  CNAME = BIG_ENDIAN_16(5),
  SOA = BIG_ENDIAN_16(6),
  PTR = BIG_ENDIAN_16(12),
  MX = BIG_ENDIAN_16(15),
  TXT = BIG_ENDIAN_16(16),
  AAAA = BIG_ENDIAN_16(28),
  SRV = BIG_ENDIAN_16(33),
  HTTPS = BIG_ENDIAN_16(65),
  ANY = BIG_ENDIAN_16(255),
};

string TypeToString(Type t) {
  switch (t) {
  case Type::A:
    return "A";
  case Type::NS:
    return "NS";
  case Type::CNAME:
    return "CNAME";
  case Type::SOA:
    return "SOA";
  case Type::PTR:
    return "PTR";
  case Type::MX:
    return "MX";
  case Type::TXT:
    return "TXT";
  case Type::AAAA:
    return "AAAA";
  case Type::SRV:
    return "SRV";
  case Type::HTTPS:
    return "HTTPS";
  case Type::ANY:
    return "ANY";
  default:
    return f("UNKNOWN(%hu)", ntohs((uint16_t)t));
  }
}

enum class Class : uint16_t {
  IN = BIG_ENDIAN_16(1),
  ANY = BIG_ENDIAN_16(255),
};

const char *ClassToString(Class c) {
  switch (c) {
  case Class::IN:
    return "IN";
  case Class::ANY:
    return "ANY";
  default:
    return "UNKNOWN";
  }
}

pair<string, size_t> LoadDomainName(const uint8_t *dns_message_base,
                                    size_t dns_message_len, size_t offset) {
  size_t start_offset = offset;
  string domain_name;
  while (true) {
    if (offset >= dns_message_len) {
      return make_pair("", 0);
    }
    uint8_t n = dns_message_base[offset++];
    if (n == 0) {
      return make_pair(domain_name, offset - start_offset);
    }
    if ((n & 0b1100'0000) == 0b1100'0000) { // DNS compression
      if (offset >= dns_message_len) {
        return make_pair("", 0);
      }
      uint16_t new_offset =
          ((n & 0b0011'1111) << 8) | dns_message_base[offset++];
      if (new_offset >=
          start_offset) { // disallow forward jumps to avoid infinite loops
        return make_pair("", 0);
      }
      auto [suffix, suffix_bytes] =
          LoadDomainName(dns_message_base, dns_message_len, new_offset);
      if (suffix_bytes == 0) {
        return make_pair("", 0);
      }
      if (!domain_name.empty()) {
        domain_name += '.';
      }
      domain_name += suffix;
      return make_pair(domain_name, offset - start_offset);
    }
    if (offset + n > dns_message_len) {
      return make_pair("", 0);
    }
    if (!domain_name.empty()) {
      domain_name += '.';
    }
    domain_name.append((char *)dns_message_base + offset, n);
    offset += n;
  }
}

string EncodeDomainName(const string &domain_name) {
  string buffer;
  size_t seg_begin = 0;
encode_segment:
  size_t seg_end = domain_name.find('.', seg_begin);
  if (seg_end == -1)
    seg_end = domain_name.size();
  size_t n = seg_end - seg_begin;
  if (n) { // don't encode 0-length segments - because \0 marks the end of
           // domain name
    buffer.append({(char)n});
    buffer.append(domain_name, seg_begin, n);
  }
  if (seg_end < domain_name.size()) {
    seg_begin = seg_end + 1;
    goto encode_segment;
  }
  buffer.append({0});
  return buffer;
}

struct Question {
  string domain_name = "";
  Type type = Type::A;
  Class class_ = Class::IN;
  size_t LoadFrom(const uint8_t *ptr, size_t len, size_t offset) {
    size_t start_offset = offset;
    auto [loaded_name, loaded_size] = LoadDomainName(ptr, len, offset);
    if (loaded_size == 0) {
      return 0;
    }
    domain_name = loaded_name;
    offset += loaded_size;
    if (offset + 4 > len) {
      return 0;
    }
    type = *(Type *)(ptr + offset);
    offset += 2;
    class_ = *(Class *)(ptr + offset);
    offset += 2;
    return offset - start_offset;
  }
  void write_to(string &buffer) const {
    string encoded = EncodeDomainName(domain_name);
    buffer.append(encoded);
    buffer.append((char *)&type, sizeof(type));
    buffer.append((char *)&class_, sizeof(class_));
  }
  string to_string() const {
    return "dns::Question(" + domain_name + ", type=" + TypeToString(type) +
           ", class=" + string(ClassToString(class_)) + ")";
  }
  bool operator==(const Question &other) const {
    return (domain_name == other.domain_name) && (type == other.type) &&
           (class_ == other.class_);
  }
  string to_html() const {
    return "<code class=\"dns-question\">" + domain_name + " " +
           TypeToString(type) + "</code>";
  }
};

struct Record : public Question {
  variant<steady_clock::time_point, steady_clock::duration> expiration;
  uint16_t data_length;
  string data;
  size_t LoadFrom(const uint8_t *ptr, size_t len, size_t offset) {
    size_t start_offset = offset;
    size_t base_size = Question::LoadFrom(ptr, len, offset);
    if (base_size == 0) {
      return 0;
    }
    offset += base_size;
    if (offset + 6 > len) {
      return 0;
    }
    expiration = steady_clock::now() +
                 chrono::seconds(ntohl(*(uint32_t *)(ptr + offset)));
    offset += 4;
    data_length = ntohs(*(uint16_t *)(ptr + offset));
    offset += 2;
    if (offset + data_length > len) {
      return 0;
    }
    if (type == Type::CNAME) {
      size_t limited_len = offset + data_length;
      auto [loaded_name, loaded_size] =
          LoadDomainName(ptr, limited_len, offset);
      if (loaded_size == 0) {
        return 0;
      }
      if (loaded_size != data_length) {
        return 0;
      }
      offset += data_length;
      // Re-encode domain name but without DNS compression
      data = EncodeDomainName(loaded_name);
      data_length = data.size();
    } else {
      data = string((const char *)(ptr + offset), data_length);
      offset += data_length;
    }
    return offset - start_offset;
  }
  void write_to(string &buffer) const {
    Question::write_to(buffer);
    uint32_t ttl_big_endian = htonl(ttl());
    buffer.append((char *)&ttl_big_endian, sizeof(ttl_big_endian));
    uint16_t data_length_big_endian = htons(data_length);
    buffer.append((char *)&data_length_big_endian,
                  sizeof(data_length_big_endian));
    buffer.append(data);
  }
  uint32_t ttl() const {
    return visit(
        overloaded{
            [&](steady_clock::time_point expiration) {
              steady_clock::duration d = expiration - steady_clock::now();
              return (uint32_t)max(d.count(), 0l);
            },
            [&](steady_clock::duration expiration) {
              return (uint32_t)duration_cast<chrono::seconds>(expiration)
                  .count();
            },
        },
        expiration);
  }
  string to_string() const {
    return "dns::Record(" + Question::to_string() +
           ", ttl=" + std::to_string(ttl()) + ", data=\"" +
           hex(data.data(), data.size()) + "\")";
  }
  string pretty_value() const {
    if (type == Type::A) {
      if (data.size() == 4) {
        return std::to_string((uint8_t)data[0]) + "." +
               std::to_string((uint8_t)data[1]) + "." +
               std::to_string((uint8_t)data[2]) + "." +
               std::to_string((uint8_t)data[3]);
      }
    } else if (type == Type::CNAME) {
      auto [loaded_name, loaded_size] =
          LoadDomainName((const uint8_t *)data.data(), data.size(), 0);
      if (loaded_size == data.size()) {
        return loaded_name;
      }
    }
    return hex(data.data(), data.size());
  }
  string to_html() const {
    return "<code class=\"dns-record\" title=\"TTL=" + std::to_string(ttl()) +
           "s\" style=\"display: inline-block\">" + domain_name + " " +
           TypeToString(type) + " " + pretty_value() + "</code>";
  }
};

struct __attribute__((__packed__)) Header {
  enum OperationCode {
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2,
    NOTIFY = 4,
    UPDATE = 5,
  };
  static string OperationCodeToString(OperationCode code) {
    switch (code) {
    case QUERY:
      return "QUERY";
    case IQUERY:
      return "IQUERY";
    case STATUS:
      return "STATUS";
    case NOTIFY:
      return "NOTIFY";
    case UPDATE:
      return "UPDATE";
    default:
      return f("UNKNOWN(%d)", code);
    }
  }
  enum ResponseCode {
    NO_ERROR = 0,
    FORMAT_ERROR = 1,
    SERVER_FAILURE = 2,
    NAME_ERROR = 3,
    NOT_IMPLEMENTED = 4,
    REFUSED = 5,
  };
  static const char *ResponseCodeToString(ResponseCode code) {
    switch (code) {
    case NO_ERROR:
      return "NO_ERROR";
    case FORMAT_ERROR:
      return "FORMAT_ERROR";
    case SERVER_FAILURE:
      return "SERVER_FAILURE";
    case NAME_ERROR:
      return "NAME_ERROR";
    case NOT_IMPLEMENTED:
      return "NOT_IMPLEMENTED";
    case REFUSED:
      return "REFUSED";
    default:
      return "UNKNOWN";
    }
  }
  uint16_t id; // big endian

  // order swapped to match the order in the packet
  bool recursion_desired : 1;
  bool truncated : 1;
  bool authoritative : 1;
  OperationCode opcode : 4;
  bool reply : 1;

  ResponseCode response_code : 4;
  uint8_t reserved : 3;
  bool recursion_available : 1;

  uint16_t question_count;   // big endian
  uint16_t answer_count;     // big endian
  uint16_t authority_count;  // big endian
  uint16_t additional_count; // big endian
  void write_to(string &buffer) {
    buffer.append((const char *)this, sizeof(*this));
  }
  string to_string() const {
    string r = "dns::Header {\n";
    r += "  id: " + f("0x%04hx", ntohs(id)) + "\n";
    r += "  reply: " + std::to_string(reply) + "\n";
    r += "  opcode: " + string(OperationCodeToString(opcode)) + "\n";
    r += "  authoritative: " + std::to_string(authoritative) + "\n";
    r += "  truncated: " + std::to_string(truncated) + "\n";
    r += "  recursion_desired: " + std::to_string(recursion_desired) + "\n";
    r += "  recursion_available: " + std::to_string(recursion_available) + "\n";
    r += "  response_code: " + string(ResponseCodeToString(response_code)) +
         "\n";
    r += "  question_count: " + std::to_string(ntohs(question_count)) + "\n";
    r += "  answer_count: " + std::to_string(ntohs(answer_count)) + "\n";
    r += "  authority_count: " + std::to_string(ntohs(authority_count)) + "\n";
    r +=
        "  additional_count: " + std::to_string(ntohs(additional_count)) + "\n";
    r += "}";
    return r;
  }
};

static_assert(sizeof(Header) == 12, "dns::Header is not packed correctly");

struct Message {
  Header header;
  Question question;
  vector<Record> answers;

  void Parse(const uint8_t *ptr, size_t len, string &err) {
    if (len < sizeof(Header)) {
      err = "DNS message buffer is too short: " + std::to_string(len) +
            " bytes. DNS header requires at least 12 bytes. Hex-escaped "
            "buffer: " +
            hex(ptr, len);
      return;
    }
    header = *(Header *)ptr;

    if (ntohs(header.question_count) != 1) {
      err =
          "DNS message contains more than one question. This is not supported.";
      return;
    }

    size_t offset = sizeof(Header);
    if (auto q_size = question.LoadFrom(ptr, len, offset)) {
      offset += q_size;
    } else {
      err = "Failed to load DNS question from " + hex(ptr, len);
      return;
    }

    for (int i = 0; i < ntohs(header.answer_count); ++i) {
      Record &r = answers.emplace_back();
      if (auto r_size = r.LoadFrom(ptr, len, offset)) {
        offset += r_size;
      } else {
        err = "Failed to load answer #" + std::to_string(i) +
              " from DNS query. Full query:\n" + hex(ptr, len);
        return;
      }
    }
  }

  string to_string() const {
    string r = "dns::Message {\n";
    r += IndentString(header.to_string()) + "\n";
    r += "  " + question.to_string() + "\n";
    for (const Record &a : answers) {
      r += "  " + a.to_string() + "\n";
    }
    r += "}";
    return r;
  }
};

struct IncomingRequest {
  Header header;
  IP client_ip;
  uint16_t client_port;
};

struct Entry;
void AnswerRequest(const IncomingRequest &request, const Entry &e, string &err);

struct Entry {
  struct Ready {
    Header::ResponseCode response_code;
    vector<Record> answers;
    string to_string() const {
      string r = "Ready(" + string(Header::ResponseCodeToString(response_code));
      for (const Record &a : answers) {
        r += "  " + a.to_string();
      }
      r += ")";
      return r;
    }
    string to_html() const {
      string r = "<code>" +
                 string(Header::ResponseCodeToString(response_code)) +
                 "</code>";
      for (const Record &a : answers) {
        r += "&nbsp;" + a.to_html();
      }
      return r;
    }
  };
  struct Pending {
    uint16_t outgoing_id;
    vector<IncomingRequest> incoming_requests;
  };

  Question question;
  mutable optional<steady_clock::time_point> expiration;
  mutable variant<Ready, Pending> state;

  void HandleIncomingRequest(const IncomingRequest &request) const {
    visit(overloaded{
              [&](Ready &r) {
                log_::Log(f("#%04hx %s:%hu Answering %s (cached)",
                            request.header.id,
                            request.client_ip.to_string().c_str(),
                            request.client_port, question.to_html().c_str()));
                string err;
                AnswerRequest(request, *this, err);
                if (!err.empty()) {
                  ERROR << err;
                }
              },
              [&](Pending &p) {
                for (auto &r : p.incoming_requests) {
                  if (r.client_ip == request.client_ip &&
                      r.client_port == request.client_port &&
                      r.header.id == request.header.id) {
                    // Ignore duplicate request
                    return;
                  }
                }
                UpdateExpiration(steady_clock::now() + 10s);
                p.incoming_requests.push_back(request);
              },
          },
          state);
  }
  void HandleAnswer(const Message &msg, string &err) const {
    auto *pending = get_if<Pending>(&state);
    if (pending == nullptr) {
      err = "Received an answer for a ready entry: " + question.to_string();
      return;
    }

    if (pending->outgoing_id != msg.header.id) {
      err = "Received an answer with an wrong ID: " +
            f("0x%04hx", msg.header.id) +
            " (expected: " + f("0x%04hx", pending->outgoing_id) + ")";
      return;
    }

    vector<IncomingRequest> incoming_requests =
        std::move(pending->incoming_requests);
    state.emplace<Ready>(
        Ready{msg.header.response_code, std::move(msg.answers)});

    steady_clock::time_point new_expiration =
        steady_clock::now() +
        (msg.header.response_code == Header::NAME_ERROR ? 60s : 24h);
    for (auto &answer : msg.answers) {
      auto record_expiration =
          get_if<steady_clock::time_point>(&answer.expiration);
      if (record_expiration == nullptr) {
        continue;
      }
      if (*record_expiration < new_expiration) {
        new_expiration = *record_expiration;
      }
    }

    UpdateExpiration(new_expiration);

    log_::Log(f("Received %s from upstream. Caching for %s.",
                question.to_html().c_str(),
                FormatDuration(new_expiration - steady_clock::now()).c_str()));

    for (auto &inc_req : incoming_requests) {
      AnswerRequest(inc_req, *this, err);
      log_::Log(f("#%04hx %s:%hu Answering %s (from upstream)",
                  inc_req.header.id, inc_req.client_ip.to_string().c_str(),
                  inc_req.client_port, msg.question.to_html().c_str()));
      if (!err.empty()) {
        break;
      }
    }
  }
  void UpdateExpiration(steady_clock::time_point new_expiration) const;
  bool operator==(const Question &other) const { return question == other; }
};

struct QuestionHash {
  using is_transparent = std::true_type;

  size_t operator()(const Question &q) const {
    return hash<string>()(q.domain_name) ^ hash<Type>()(q.type) ^
           hash<Class>()(q.class_);
  }
  size_t operator()(const Entry &e) const { return (*this)(e.question); }
  size_t operator()(const Entry *e) const { return (*this)(*e); }
};

struct QuestionEqual {
  using is_transparent = std::true_type;

  bool operator()(const Entry &a, const Entry &b) const {
    return a.question == b.question;
  }
  bool operator()(const Entry *a, const Entry *b) const {
    return a->question == b->question;
  }
  bool operator()(const Question &a, const Entry &b) const {
    return a == b.question;
  }
  bool operator()(const Question &a, const Entry *b) const {
    return a == b->question;
  }
};

unordered_set<const Entry *, QuestionHash, QuestionEqual> cache;

unordered_set<Entry, QuestionHash, QuestionEqual> static_cache;

multimap<steady_clock::time_point, const Entry *> expiration_queue;

void Entry::UpdateExpiration(steady_clock::time_point new_expiration) const {
  if (expiration) {
    auto [begin, end] = expiration_queue.equal_range(*expiration);
    for (auto it = begin; it != end; ++it) {
      if (it->second == this) {
        expiration_queue.erase(it);
        break;
      }
    }
  }
  expiration = new_expiration;
  expiration_queue.emplace(new_expiration, this);
}

void ExpireEntries() {
  auto now = steady_clock::now();
  while (!expiration_queue.empty() && expiration_queue.begin()->first < now) {
    log_::Log("Expiring " +
              expiration_queue.begin()->second->question.to_html());
    cache.erase(expiration_queue.begin()->second);
    expiration_queue.erase(expiration_queue.begin());
  }
}

const Entry *GetCachedEntry(const Question &question) {
  if (question.domain_name.ends_with("." + kLocalDomain)) {
    auto it = static_cache.find(question);
    if (it != static_cache.end()) {
      it->expiration = steady_clock::now() + 1h;
      return &*it;
    }
    static Entry name_not_found_entry =
        Entry{.state = Entry::Ready{Header::NAME_ERROR, {}}};
    name_not_found_entry.question = question;
    name_not_found_entry.expiration = steady_clock::now() + 60s;
    return &name_not_found_entry;
  } else {
    auto it = cache.find(question);
    if (it == cache.end()) {
      return nullptr;
    }
    return *it;
  }
}

struct Client : UDPListener {
  uint16_t request_id;
  int server_i = 0;

  uint16_t AllocateRequestId() {
    return request_id = htons(ntohs(request_id) + 1);
  }

  void Listen(string &error) {
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
      error = "socket";
      return;
    }

    SetNonBlocking(fd, error);
    if (!error.empty()) {
      StopListening();
      return;
    }

    epoll::Add(this, error);
  }

  // Stop listening.
  void StopListening() {
    string error_ignored;
    epoll::Del(this, error_ignored);
    shutdown(fd, SHUT_RDWR);
    close(fd);
  }

  void HandleRequest(string_view buf, IP source_ip,
                     uint16_t source_port) override {
    if (find(etc::resolv.begin(), etc::resolv.end(), source_ip) ==
        etc::resolv.end()) {
      string dns_servers = "";
      for (const auto &server : etc::resolv) {
        if (!dns_servers.empty()) {
          dns_servers += " / ";
        }
        dns_servers += server.to_string();
      }
      log_::Log("DNS client received a packet from an unexpected source: " +
                source_ip.to_string() + " (expected: " + dns_servers + ")");
      return;
    }
    if (source_port != kServerPort) {
      log_::Log(
          "DNS client received a packet from an unexpected source port: " +
          to_string(source_port) + " (expected port " + to_string(kServerPort) +
          ")");
      return;
    }
    Message msg;
    string err;
    msg.Parse((const uint8_t *)buf.data(), buf.size(), err);
    if (!err.empty()) {
      ERROR << err;
      return;
    }

    if (msg.header.opcode != Header::QUERY) {
      log_::Log("DNS client received a packet with an unsupported opcode: " +
                Header::OperationCodeToString(msg.header.opcode) +
                ". Full query: " + msg.header.to_string());
      return;
    }

    if (!msg.header.reply) {
      log_::Log("DNS client received a packet that is not a reply: " +
                msg.header.to_string());
      return;
    }

    const Entry *entry = GetCachedEntry(msg.question);
    if (entry == nullptr) {
      log_::Log("DNS client received an unexpected / expired reply: " +
                msg.question.to_string());
      return;
    }
    entry->HandleAnswer(msg, err);
    if (!err.empty()) {
      ERROR << err;
      return;
    }
  }

  void NotifyRead(string &abort_error) override {
    ExpireEntries();
    UDPListener::NotifyRead(abort_error);
  }

  const Entry &GetCachedEntryOrSendRequest(const Question &question,
                                           string &err) {
    const Entry *entry = GetCachedEntry(question);
    if (entry == nullptr) {
      // Send a request to the upstream DNS server.
      uint16_t id = AllocateRequestId();
      Entry *new_entry = new Entry{
          .question = question,
          .expiration = steady_clock::now() + 10s,
          .state = Entry::Pending{id, {}},
      };
      new_entry->UpdateExpiration(steady_clock::now() + 10s);
      entry = new_entry;
      cache.insert(entry);
      string buffer;
      Header{.id = id, .recursion_desired = true, .question_count = htons(1)}
          .write_to(buffer);
      question.write_to(buffer);
      IP upstream_ip =
          etc::resolv[(++server_i) % etc::resolv.size()]; // Round-robin
      ::SendTo(fd, buffer, upstream_ip, kServerPort, err);
      if (err.empty()) {
        log_::Log(f("Forwarding %s.", question.to_html().c_str()));
      }
    }
    return *entry;
  }

  const char *Name() const override { return "dns::Client"; }
};

Client client;

struct Server : UDPListener {

  // Start listening.
  //
  // To actually accept new connections, make sure to Poll the `epoll`
  // instance after listening.
  void Listen(string &error) {
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
      error = "socket";
      return;
    }

    SetNonBlocking(fd, error);
    if (!error.empty()) {
      StopListening();
      return;
    }

    int flag = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag)) <
        0) {
      error = "setsockopt: SO_REUSEADDR";
      StopListening();
      return;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface_name.data(),
                   interface_name.size()) < 0) {
      error = "Error when setsockopt bind to device";
      StopListening();
      return;
    };

    sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(kServerPort),
        .sin_addr = {.s_addr = htonl(INADDR_ANY)},
    };

    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
      error = "bind: ";
      error += strerror(errno);
      StopListening();
      return;
    }

    epoll::Add(this, error);
  }

  // Stop listening.
  void StopListening() {
    string error_ignored;
    epoll::Del(this, error_ignored);
    shutdown(fd, SHUT_RDWR);
    close(fd);
  }

  void SendTo(const string &buffer, IP ip, uint16_t port, string &error) {
    ::SendTo(fd, buffer, ip, port, error);
  }

  void HandleRequest(string_view buf, IP source_ip,
                     uint16_t source_port) override {
    if ((source_ip & netmask) != (server_ip & netmask)) {
      log_::Log("DNS server received a packet from an unexpected source: " +
                source_ip.to_string() + " (expected network " +
                (server_ip & netmask).to_string() + ")");
      return;
    }
    Message msg;
    string err;
    msg.Parse((const uint8_t *)buf.data(), buf.size(), err);
    if (!err.empty()) {
      ERROR << err;
      return;
    }

    if (msg.header.opcode != Header::QUERY) {
      log_::Log("DNS server received a packet with an unsupported opcode: " +
                Header::OperationCodeToString(msg.header.opcode) +
                ". Full query: " + msg.header.to_string());
      return;
    }

    log_::Log(f("#%04hx %s:%hu Asks for %s", msg.header.id,
                source_ip.to_string().c_str(), source_port,
                msg.question.to_html().c_str()));

    const Entry &entry = client.GetCachedEntryOrSendRequest(msg.question, err);
    if (!err.empty()) {
      ERROR << err;
      return;
    }
    entry.HandleIncomingRequest(IncomingRequest{
        .header = msg.header,
        .client_ip = source_ip,
        .client_port = source_port,
    });
  }

  void NotifyRead(string &abort_error) override {
    ExpireEntries();
    UDPListener::NotifyRead(abort_error);
  }

  const char *Name() const override { return "dns::Server"; }
};

Server server;

void AnswerRequest(const IncomingRequest &request, const Entry &e,
                   string &err) {
  const Entry::Ready *r = get_if<Entry::Ready>(&e.state);
  if (r == nullptr) {
    err = "AnswerRequest called on an entry that is not ready";
    return;
  }
  string buffer;
  Header response_header{
      .id = request.header.id,
      .recursion_desired = true,
      .truncated = false,
      .authoritative = false,
      .opcode = Header::QUERY,
      .reply = true,
      .response_code = r->response_code,
      .reserved = 0,
      .recursion_available = true,
      .question_count = htons(1),
      .answer_count = htons(r->answers.size()),
      .authority_count = 0,
      .additional_count = 0,
  };
  response_header.write_to(buffer);
  e.question.write_to(buffer);
  for (auto &a : r->answers) {
    a.write_to(buffer);
  }
  server.SendTo(buffer, request.client_ip, request.client_port, err);
}

void InjectAuthoritativeEntry(const string &domain, IP ip) {
  string encoded_domain = EncodeDomainName(domain);
  static_cache.insert(Entry{
      .question = Question{.domain_name = domain},
      .expiration = std::nullopt,
      .state = Entry::Ready{
          .response_code = Header::NO_ERROR,
          .answers = {Record{Question{.domain_name = domain}, kAuthoritativeTTL,
                             (uint16_t)sizeof(ip.addr),
                             string((char *)&ip.addr, sizeof(ip.addr))}}}});
}

void Start(string &err) {
  client.request_id = random<uint16_t>(); // randomize initial request ID

  for (auto &[ip, aliases] : etc::hosts) {
    if (ip.bytes[0] == 127) {
      continue;
    }
    for (auto &alias : aliases) {
      string domain = alias + "." + kLocalDomain;
      InjectAuthoritativeEntry(domain, ip);
    }
  }
  InjectAuthoritativeEntry(etc::hostname + "." + kLocalDomain, server_ip);
  client.Listen(err);
  if (!err.empty()) {
    err = "Failed to start DNS client: " + err;
    return;
  }
  server.Listen(err);
  if (!err.empty()) {
    err = "Failed to start DNS server: " + err;
    return;
  }
}

} // namespace dns

namespace http {

static constexpr int kPort = 1337;
Server server;

void WriteFile(Response &response, const char *path) {
  int f = open(path, O_RDONLY);
  if (f == -1) {
    response.WriteStatus("500 Internal Server Error");
    response.Write("Failed to open style.css");
    return;
  }
  char buf[1024 * 64];
  int len = read(f, buf, sizeof(buf));
  close(f);
  if (len == -1) {
    response.WriteStatus("500 Internal Server Error");
    response.Write("Failed to read style.css");
    return;
  }
  response.Write(string_view(buf, len));
}

unordered_set<string> static_files = {
    "/style.css",
    "/knight.gif",
    "/favicon.ico",
};

void Handler(Response &response, Request &request) {
  string path(request.path);
  if (static_files.contains(path)) {
    WriteFile(response, path.substr(1).c_str());
    return;
  }
  steady_clock::time_point now = steady_clock::now();
  string html;
  html.reserve(1024 * 64);
  html += "<!doctype html>";
  html += "<html><head><title>Gatekeeper</title><link rel=\"stylesheet\" "
          "href=\"/style.css\"><link rel=\"icon\" type=\"image/x-icon\" "
          "href=\"/favicon.ico\"></head><body>";
  html += R"(<script>
if (localStorage.refresh) {
  window.refresh_timeout = setTimeout(() => location.reload(), 1000);
}
function ToggleAutoRefresh() {
  if (localStorage.refresh) {
    delete localStorage.refresh;
  } else {
    localStorage.refresh = true;
  }
  location.reload();
}
</script>)";
  html += "<h1><a target=\"_blank\" "
          "href=\"https://github.com/mafik/gatekeeper\"><img "
          "src=\"/knight.gif\" id=\"knight\"></a>Gatekeeper <button "
          "onclick=\"ToggleAutoRefresh()\">Toggle Auto-refresh</button></h1>";
  auto table = [&](const char *caption, initializer_list<const char *> headers,
                   function<void()> inner) {
    html += "<table><caption>";
    html += caption;
    html += "</caption>";
    if (headers.size()) {
      html += "<tr>";
      for (auto &h : headers) {
        html += "<th>";
        html += h;
        html += "</th>";
      }
      html += "</tr>";
    }
    inner();
    html += "</table>";
  };
  table("Config", {"Key", "Value"}, [&]() {
    auto row = [&](const char *key, const string &value) {
      html += "<tr><td>";
      html += key;
      html += "</td><td>";
      html += value;
      html += "</td></tr>";
    };
    row("interface", interface_name);
    row("domain_name", kLocalDomain);
    row("server_ip", server_ip.to_string());
    row("netmask", netmask.to_string());
    row("/etc/hostname", etc::hostname);
  });
  table("/etc/hosts", {"hostname", "IP"}, [&]() {
    for (auto &[ip, aliases] : etc::hosts) {
      for (auto &alias : aliases) {
        html += "<tr><td>";
        html += alias;
        html += "</td><td>";
        html += ip.to_string();
        html += "</td></tr>";
      }
    }
  });
  table("/etc/ethers", {"MAC", "IP"}, [&]() {
    for (auto &[mac, ip] : etc::ethers) {
      html += "<tr><td>";
      html += mac.to_string();
      html += "</td><td>";
      html += ip.to_string();
      html += "</td></tr>";
    }
  });
  table("/etc/resolv.conf", {"IP"}, [&]() {
    for (auto &ip : etc::resolv) {
      html += "<tr><td>";
      html += ip.to_string();
      html += "</td></tr>";
    }
  });
  table("DHCP",
        {"IP", "Client ID", "Hostname", "TTL", "Last activity", "Stable"},
        [&]() {
          for (auto &[ip, entry] : dhcp::server.entries) {
            html += "<tr><td>";
            html += ip.to_string();
            html += "</td><td>";
            html += entry.client_id;
            html += "</td><td>";
            html += entry.hostname;
            html += "</td><td>";
            html += FormatDuration(
                entry.expiration.transform([&](auto e) { return e - now; }));
            html += "</td><td>";
            html += FormatDuration(
                entry.last_request.transform([&](auto x) { return x - now; }),
                "never");
            html += "</td><td>";
            html += entry.stable ? "✓" : "";
            html += "</td></tr>";
          }
        });
  table("Log", {"Message"}, [&]() {
    for (auto &line : log_::messages) {
      html += "<tr><td>";
      html += line;
      html += "</td></tr>";
    }
  });
  table("DNS cache", {"Question", "TTL", "State"}, [&]() {
    auto emit_dns_entry = [&](const dns::Entry &entry) {
      html += "<tr><td>";
      html += entry.question.to_html();
      html += "</td><td>";
      html += FormatDuration(
          entry.expiration.transform([&](auto e) { return e - now; }));
      html += "</td><td>";
      visit(
          overloaded{
              [&](const dns::Entry::Ready &ready) { html += ready.to_html(); },
              [&](const dns::Entry::Pending &pending) { html += "Pending"; }},
          entry.state);
      html += "</td></tr>";
    };

    for (auto &entry : dns::static_cache) {
      emit_dns_entry(entry);
    }
    for (auto &entry : dns::cache) {
      emit_dns_entry(*entry);
    }
  });
  html += "</body></html>";
  response.Write(html);
}

void Start(string &err) {
  server.handler = Handler;
  server.Listen(http::Server::Config{.ip = server_ip,
                                     .port = http::kPort,
                                     .interface = interface_name},
                err);
  if (!err.empty()) {
    return;
  }
}

} // namespace http

int main(int argc, char *argv[]) {
  string err;

  if (argc < 2) {
    ERROR << "Usage: " << argv[0] << " <interface>";
    return 1;
  }
  interface_name = argv[1];

  epoll::Init();

  server_ip = IP::FromInterface(interface_name, err);
  if (!err.empty()) {
    ERROR << "Couldn't obtain IP for interface " << interface_name << ": "
          << err;
    return 1;
  }
  netmask = IP::NetmaskFromInterface(interface_name, err);
  if (!err.empty()) {
    ERROR << "Couldn't obtain netmask for interface " << interface_name << ": "
          << err;
    return 1;
  }

  etc::ReadConfig();

  dhcp::server.Init();
  dhcp::server.Listen(err);
  if (!err.empty()) {
    ERROR << "Failed to start DHCP server: " << err;
    return 1;
  }

  dns::Start(err);
  if (!err.empty()) {
    ERROR << err;
    return 1;
  }

  http::Start(err);
  if (!err.empty()) {
    ERROR << err;
    return 1;
  }

  log_::Log("Gatekeeper started.");
  epoll::Loop(err);
  if (!err.empty()) {
    ERROR << err;
    return 1;
  }
  return 0;
}
