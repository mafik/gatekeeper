#pragma once

#include <memory>

namespace maf {

template <typename T> using UniquePtr = std::unique_ptr<T>;

} // namespace maf