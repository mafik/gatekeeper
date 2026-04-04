#include "args.hh"

namespace automat {

int argc;
char **argv;

__attribute__((constructor)) void InitArgs(int _argc, char **_argv) {
  argc = _argc;
  argv = _argv;
}

} // namespace automat