#pragma once

#include "status.hh"

namespace maf::dns {

void StartServer(Status &);
void StopServer();

} // namespace maf::dns