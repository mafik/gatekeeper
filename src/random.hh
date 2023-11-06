#pragma once

#include <random>

#include "span.hh"

extern std::mt19937 generator;

template <typename T> T random() {
  std::uniform_int_distribution<T> distr(std::numeric_limits<T>::min(),
                                         std::numeric_limits<T>::max());
  return distr(generator);
}

namespace maf {

// This function may block if there is not enough entropy available.
//
// See `man 2 getrandom` for more information.
void RandomBytesSecure(Span<> out);

} // namespace maf