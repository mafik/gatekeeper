#include "big_endian.hh"
#include "int.hh"

namespace maf {

template <> void AppendBigEndian(MemBuf &s, U16 x) {
  s.insert(s.end(), {(U8)(x >> 8), (U8)(x & 0xff)});
}

template <> void AppendBigEndian(MemBuf &s, U24 x) {
  s.insert(s.end(), {(U8)(x >> 16), (U8)(x >> 8), (U8)(x & 0xff)});
}

template <> void PutBigEndian(MemView s, Size offset, U16 x) {
  s[offset] = (U8)(x >> 8);
  s[offset + 1] = (U8)(x & 0xff);
}

template <> void PutBigEndian(MemView s, Size offset, U24 x) {
  s[offset] = (U8)(x >> 16);
  s[offset + 1] = (U8)(x >> 8);
  s[offset + 2] = (U8)(x & 0xff);
}

template <> U24 PeekBigEndian(MemView s) {
  if (s.size() < 3) {
    return 0;
  }
  U24 x = (U8)s[0] << 16 | (U8)s[1] << 8 | (U8)s[2];
  return x;
}

template <> U8 ConsumeBigEndian(MemView &s) {
  if (s.size() < 1) {
    return 0;
  }
  U8 x = (U8)s[0];
  s = s.subspan<1>();
  return x;
}

template <> U16 ConsumeBigEndian(MemView &s) {
  if (s.size() < 2) {
    return 0;
  }
  U16 x = (U8)s[0] << 8 | (U8)s[1];
  s = s.subspan<2>();
  return x;
}

template <> U24 ConsumeBigEndian(MemView &s) {
  auto x = PeekBigEndian<U24>(s);
  s = s.subspan<3>();
  return x;
}

} // namespace maf