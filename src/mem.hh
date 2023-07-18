#pragma once

#include "int.hh"
#include "span.hh"
#include "str.hh"
#include "vec.hh"

namespace maf {

using MemView = Span<U8>;

using MemBuf = Vec<U8>;

inline MemView MemViewOf(const Str &s) {
  return MemView((U8 *)s.data(), s.size());
}

inline MemView MemViewOf(StrView s) {
  return MemView((U8 *)s.data(), s.size());
}

inline MemView operator""_MemView(const char *str, size_t len) {
  return MemView((U8 *)str, len);
}

template <size_t N>
inline constexpr Span<const U8, N - 1> StrSpan(const char (&str)[N]) {
  return Span<const U8, N - 1>((const U8 *)str, N - 1);
}

} // namespace maf