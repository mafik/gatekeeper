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

} // namespace maf