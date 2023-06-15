#pragma once

#include <map>
#include <string>
#include <vector>

#include "ip.hh"
#include "mac.hh"

namespace etc {

using std::map;
using std::string;
using std::vector;

extern map<IP, vector<string>> hosts;
extern map<MAC, IP> ethers;
extern vector<IP> resolv;
extern string hostname;

// Read files from /etc/ and populate global variables.
void ReadConfig();

} // namespace etc
