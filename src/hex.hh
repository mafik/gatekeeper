#pragma once

#include "arr.hh"
#include "span.hh"
#include "str.hh"
#include "vec.hh"

namespace maf {

void HexToBytesUnchecked(StrView hex, char *out_bytes);

Str BytesToHex(Span<> bytes);

inline Str BytesToHex(const char *bytes, size_t len) {
  return BytesToHex(Span<>{const_cast<char *>(bytes), len});
}

template <typename T> inline Str ValToHex(T &val) {
  return BytesToHex(Span<>((char *)(&val), sizeof(T)));
}

inline Vec<> operator""_HexVec(const char *str, size_t len) {
  Vec buf;
  buf.resize(len / 2);
  HexToBytesUnchecked({str, len}, buf.data());
  return buf;
}

template <size_t N> Arr<char, (N - 1) / 2> HexArr(const char (&str)[N]) {
  Arr<char, (N - 1) / 2> arr;
  HexToBytesUnchecked(StrView(str, N - 1), arr.data());
  return arr;
}

} // namespace maf