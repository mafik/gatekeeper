#include "atexit.hh"

#include "vec.hh"

namespace maf {

Vec<Fn<void()>> at_exit_functions;

void AtExit(Fn<void()> f) {
  static bool initialized = false;
  if (!initialized) {
    atexit(ExitCleanup);
    initialized = true;
  }
  at_exit_functions.push_back(std::move(f));
}

void ExitCleanup() {
  while (!at_exit_functions.empty()) {
    at_exit_functions.back()();
    at_exit_functions.pop_back();
  }
}

} // namespace maf