#pragma once

namespace maf {

using I8 = signed char;
using I16 = signed short;
using I32 = signed int;
using I64 = signed long;
using I128 = __int128; // _BitInt(128);

static_assert(sizeof(I64) == 8);

using U8 = unsigned char;
using U16 = unsigned short;

struct U24 {
  unsigned int data : 24;
  U24(unsigned int x) : data(x) {}
  operator unsigned int() const { return data; }
} __attribute__((__packed__));

// using U24 = unsigned _BitInt(24);

using U32 = unsigned int;
using U64 = unsigned long;
using U128 = unsigned __int128; // _BitInt(128);

using Size = unsigned long;
using SSize = signed long;

} // namespace maf