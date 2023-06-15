#pragma once

#include <random>

extern std::mt19937 generator;

template <typename T> T random() {
  std::uniform_int_distribution<T> distr(std::numeric_limits<T>::min(),
                                         std::numeric_limits<T>::max());
  return distr(generator);
}
