#pragma once

#include <functional>

// Shortcut for std::function
namespace maf {

template <typename T> using Fn = std::function<T>;

} // namespace maf