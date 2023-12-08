#include "big_endian.hh"
#include "int.hh"

namespace maf {

template <> void AppendBigEndian(Vec<> &s, U16 x) {
  s.insert(s.end(), {(char)(x >> 8), (char)(x & 0xff)});
}

template <> void AppendBigEndian(Vec<> &s, U24 x) {
  s.insert(s.end(), {(char)(x >> 16), (char)(x >> 8), (char)(x & 0xff)});
}

template <> void AppendBigEndian(Vec<> &s, U32 x) {
  s.insert(s.end(), {(char)(x >> 24), (char)(x >> 16), (char)(x >> 8),
                     (char)(x & 0xff)});
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

} // namespace maf