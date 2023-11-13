#pragma once

#include "int.hh"
#include "span.hh"
#include "vec.hh"

#include <bit>

namespace maf {

template <typename T> void AppendBigEndian(Vec<> &s, T x);

template <> void AppendBigEndian(Vec<> &s, U16 x);
template <> void AppendBigEndian(Vec<> &s, U24 x);
template <> void AppendBigEndian(Vec<> &s, U32 x);

template <typename T> void PutBigEndian(Span<> s, Size offset, T x);

template <> void PutBigEndian(Span<> s, Size offset, U16 x);
template <> void PutBigEndian(Span<> s, Size offset, U24 x);

template <typename T> T PeekBigEndian(Span<> s);

template <> U24 PeekBigEndian(Span<> s);

template <typename T> T ConsumeBigEndian(Span<> &s);

template <> U8 ConsumeBigEndian(Span<> &s);
template <> U16 ConsumeBigEndian(Span<> &s);
template <> U24 ConsumeBigEndian(Span<> &s);
template <> U32 ConsumeBigEndian(Span<> &s);

template <typename T> struct Big {
  T big_endian;

  Big() = default;
  Big(T host_value) : big_endian(std::byteswap(host_value)) {}

  T Get() const { return std::byteswap(big_endian); }
  void Set(T value) { big_endian = std::byteswap(value); }
} __attribute__((packed));

} // namespace maf