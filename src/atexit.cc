#include "atexit.hh"

#include "vec.hh"

namespace maf {

Vec<Fn<void()>> at_exit_functions;

__attribute__((constructor)) void InitAtExit() { atexit(ExitCleanup); }

void AtExit(Fn<void()> f) { at_exit_functions.push_back(std::move(f)); }

void ExitCleanup() {
  for (auto &f : at_exit_functions) {
    f();
  }
}

} // namespace maf