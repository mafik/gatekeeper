#pragma once

#include <functional>

// Shortcut for std::function
namespace maf {

template <typename T> using Fn = std::function<T>;

template <typename T> struct FnIs {
  const T *bare_ptr;
  FnIs(T *bare_ptr) : bare_ptr(bare_ptr) {}

  bool operator()(const Fn<T> &fn) const {
    return fn.template target<T>() == bare_ptr;
  }
};

} // namespace maf