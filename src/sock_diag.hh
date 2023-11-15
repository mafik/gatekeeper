#pragma once

// Functions for querying information about sockets (UNIX, TCP/UDP/UDPLITE).

#include "fn.hh"
#include "int.hh"
#include "ip.hh"

namespace maf {

struct PacketSocketDescription {
  U16 protocol;
  U32 inode;
};

void ScanPacketSockets(Fn<void(PacketSocketDescription &)> callback,
                       Status &status);

struct InternetSocketDescription {
  IP local_ip;
  U16 local_port;
  IP remote_ip;
  U16 remote_port;
  U32 inode;
  U32 uid;
  U32 interface;
};

// Scan listening ports and call callback for each one.
void ScanUdpSockets(Fn<void(InternetSocketDescription &)> callback,
                    Status &status);

// Scan listening ports and call callback for each one.
void ScanTcpSockets(Fn<void(InternetSocketDescription &)> callback,
                    Status &status);

} // namespace maf