#include "nfqueue.hh"

namespace maf::netfilter {

thread_local uint16_t default_queue = 1337;

} // namespace maf::netfilter