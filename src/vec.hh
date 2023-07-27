#pragma once

#include <vector>

namespace maf {

template <typename T = char> struct Vec : std::vector<T> {
  using std::vector<T>::vector;
};

} // namespace maf