#pragma once

#include "int.hh"
#include "mem.hh"
#include <bit>

namespace maf {

template <typename T> void AppendBigEndian(MemBuf &s, T x);

template <> void AppendBigEndian(MemBuf &s, U16 x);
template <> void AppendBigEndian(MemBuf &s, U24 x);

template <typename T> void PutBigEndian(MemView s, Size offset, T x);

template <> void PutBigEndian(MemView s, Size offset, U16 x);
template <> void PutBigEndian(MemView s, Size offset, U24 x);

template <typename T> T PeekBigEndian(MemView s);

template <> U24 PeekBigEndian(MemView s);

template <typename T> T ConsumeBigEndian(MemView &s);

template <> U8 ConsumeBigEndian(MemView &s);
template <> U16 ConsumeBigEndian(MemView &s);
template <> U24 ConsumeBigEndian(MemView &s);

template <typename T> struct Big {
  T big_endian;

  Big() = default;
  Big(T host_value) : big_endian(std::byteswap(host_value)) {}

  T get() const { return std::byteswap(big_endian); }
} __attribute__((packed));

} // namespace maf