#pragma once

#include "int.hh"
#include "vec.hh"

#include <bit>

namespace std {

template <> constexpr maf::U24 byteswap(maf::U24 x) noexcept {
  return (x & 0x0000ff) << 16 | (x & 0x00ff00) | (x & 0xff0000) >> 16;
}

} // namespace std

namespace maf {

template <typename T> void AppendBigEndian(Vec<> &s, T x);

template <> void AppendBigEndian(Vec<> &s, U16 x);
template <> void AppendBigEndian(Vec<> &s, U24 x);
template <> void AppendBigEndian(Vec<> &s, U32 x);

template <typename T> struct Big {
  T big_endian;

  Big() = default;
  constexpr Big(T host_value) : big_endian(std::byteswap(host_value)) {}

  T Get() const { return std::byteswap(big_endian); }
  void Set(T host_value) { big_endian = std::byteswap(host_value); }
  operator T() const { return Get(); }
} __attribute__((packed));

static_assert(Big<U16>(0x1122).big_endian == 0x2211);
static_assert(Big<U24>(0x112233).big_endian == 0x332211);
static_assert(Big<U32>(0x11223344).big_endian == 0x44332211);
static_assert(Big<U64>(0x1122334455667788).big_endian == 0x8877665544332211);

} // namespace maf