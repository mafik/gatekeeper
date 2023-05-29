#pragma once

#include <cstdlib>

struct FreeDeleter {
  void operator()(void *p) { free(p); }
};
