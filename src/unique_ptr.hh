#pragma once

#include <memory>

namespace automat {

template <typename T> using UniquePtr = std::unique_ptr<T>;

} // namespace automat