#include "etc.hh"

#include <fstream>
#include <sstream>

using namespace std;

namespace etc {

map<IP, vector<string>> hosts;
std::map<MAC, IP> ethers;
std::vector<IP> resolv = {IP(8, 8, 8, 8), IP(8, 8, 4, 4)};
std::string hostname = "localhost";

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

std::vector<IP> ReadResolv() {
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

std::string ReadHostname() {
  ifstream hostname_stream("/etc/hostname");
  string hostname;
  getline(hostname_stream, hostname);
  return hostname;
}

void ReadConfig() {
  hosts = ReadHosts();
  ethers = ReadEthers(hosts);
  resolv = ReadResolv();
  hostname = ReadHostname();
}

} // namespace etc