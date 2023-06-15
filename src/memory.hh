#pragma once

#include <cstdlib>
#include <memory>

struct FreeDeleter {
  void operator()(void *p) { free(p); }
};
