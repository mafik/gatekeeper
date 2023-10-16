#include "etc.hh"

#include <fstream>
#include <sstream>

using namespace std;

namespace etc {

map<IP, Vec<Str>> hosts;
map<MAC, IP> ethers;
Vec<IP> resolv = {IP(8, 8, 8, 8), IP(8, 8, 4, 4)};
Str hostname = "localhost";

Vec<Str> *GetHosts(MAC mac) {
  if (auto ethers_it = ethers.find(mac); ethers_it != ethers.end()) {
    if (auto hosts_it = hosts.find(ethers_it->second);
        hosts_it != hosts.end()) {
      return &hosts_it->second;
    }
  }
  return nullptr;
}

map<IP, Vec<Str>> ReadHosts() {
  map<IP, Vec<Str>> etc_hosts;
  ifstream hosts_stream("/etc/hosts");
  Str line;
  while (getline(hosts_stream, line)) {
    if (auto pos = line.find("#"); pos != Str::npos) {
      line.resize(pos);
    }
    istringstream iss(line);
    Str ip_str;
    if (!(iss >> ip_str)) {
      continue;
    }
    IP ip;
    if (!ip.TryParse(ip_str.c_str())) {
      continue;
    }
    Str hostname;
    while (iss >> hostname) {
      etc_hosts[ip].push_back(hostname);
    }
  }
  return etc_hosts;
}

map<MAC, IP> ReadEthers(const map<IP, Vec<Str>> &etc_hosts) {
  map<MAC, IP> etc_ethers;
  ifstream ethers_stream("/etc/ethers");
  Str line;
  while (getline(ethers_stream, line)) {
    if (auto pos = line.find("#"); pos != Str::npos) {
      line.resize(pos);
    }
    istringstream iss(line);
    Str mac_str;
    Str addr_str;
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
    outer:;
    }
  }
  return etc_ethers;
}

Vec<IP> ReadResolv() {
  Vec<IP> resolv;
  ifstream resolv_stream("/etc/resolv.conf");
  Str line;
  while (getline(resolv_stream, line)) {
    if (auto pos = line.find("#"); pos != Str::npos) {
      line.resize(pos);
    }
    istringstream iss(line);
    Str keyword;
    if (!(iss >> keyword)) {
      continue;
    }
    if (keyword == "nameserver") {
      Str ip_str;
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

Str ReadHostname() {
  ifstream hostname_stream("/etc/hostname");
  Str hostname;
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