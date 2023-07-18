#pragma once

#include <span>

namespace maf {

template <class T, std::size_t Extent = std::dynamic_extent>
using Span = std::span<T, Extent>;

} // namespace maf
