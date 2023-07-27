#include "big_endian.hh"
#include "int.hh"

namespace maf {

template <> void AppendBigEndian(Vec<> &s, U16 x) {
  s.insert(s.end(), {(char)(x >> 8), (char)(x & 0xff)});
}

template <> void AppendBigEndian(Vec<> &s, U24 x) {
  s.insert(s.end(), {(char)(x >> 16), (char)(x >> 8), (char)(x & 0xff)});
}

template <> void PutBigEndian(Span<> s, Size offset, U16 x) {
  s[offset] = (char)(x >> 8);
  s[offset + 1] = (char)(x & 0xff);
}

template <> void PutBigEndian(Span<> s, Size offset, U24 x) {
  s[offset] = (char)(x >> 16);
  s[offset + 1] = (char)(x >> 8);
  s[offset + 2] = (char)(x & 0xff);
}

template <> U24 PeekBigEndian(Span<> s) {
  if (s.size() < 3) {
    return 0;
  }
  U24 x = (U8)s[0] << 16 | (U8)s[1] << 8 | (U8)s[2];
  return x;
}

template <> U8 ConsumeBigEndian(Span<> &s) {
  if (s.size() < 1) {
    return 0;
  }
  U8 x = (U8)s[0];
  s = s.subspan<1>();
  return x;
}

template <> U16 ConsumeBigEndian(Span<> &s) {
  if (s.size() < 2) {
    return 0;
  }
  U16 x = (U8)s[0] << 8 | (U8)s[1];
  s = s.subspan<2>();
  return x;
}

template <> U24 ConsumeBigEndian(Span<> &s) {
  auto x = PeekBigEndian<U24>(s);
  s = s.subspan<3>();
  return x;
}

template <> U32 ConsumeBigEndian(Span<> &s) {
  if (s.size() < 4) {
    return 0;
  }
  U32 x = s[0] << 24 | s[1] << 16 | s[2] << 8 | s[3];
  s = s.subspan<4>();
  return x;
}

} // namespace maf