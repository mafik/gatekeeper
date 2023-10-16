#pragma once

#include <map>
#include <string>
#include <vector>

#include "ip.hh"
#include "mac.hh"
#include "optional.hh"
#include "str.hh"
#include "vec.hh"

namespace etc {

using std::map;
using namespace maf;

extern map<IP, Vec<Str>> hosts;
extern map<MAC, IP> ethers;
extern Vec<IP> resolv;
extern Str hostname;

// Return a list of /etc/hosts aliases for the given MAC address.
//
// This uses /etc/ethers to map MAC addresses to IP addresses, and then
// /etc/hosts to map IP addresses to a list of aliases.
Vec<Str> *GetHosts(MAC);

// Read files from /etc/ and populate global variables.
void ReadConfig();

} // namespace etc
