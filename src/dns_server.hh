#pragma once

#include "status.hh"

namespace automat::dns {

void StartServer(Status &);
void StopServer();

} // namespace automat::dns