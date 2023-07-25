#pragma once

#include "int.hh"
#include "mem.hh"
#include "str.hh"

namespace maf {

struct SHA1 {
  U8 bytes[20];

  SHA1(MemView);

  operator MemView() { return bytes; }
  operator StrView() { return StrView((const char *)bytes, 20); }
};

struct SHA256 {
  constexpr static size_t kBlockSize = 64;

  U8 bytes[32];

  // Construct an uninitialized SHA256. There shoud be no reason to use this
  // function except to reserve space for a proper SHA256.
  SHA256() = default;

  // Compute a SHA256 of a memory buffer in one go.
  SHA256(Span<const U8>);
  SHA256(StrView s) : SHA256(Span<const U8>((const U8 *)s.data(), s.size())) {}

  struct Builder {
    U32 state[8];
    U8 buffer[64];
    U64 n_bits;
    U8 buffer_counter;
    Builder();
    Builder &Update(Span<const U8>);
    SHA256 Finalize();
  };

  operator MemView() { return bytes; }
  operator Span<const U8>() const { return bytes; }
};

struct SHA512 {
  U8 bytes[64];

  // Construct an uninitialized SHA512. There shoud be no reason to use this
  // function except to reserve space for a proper SHA512.
  SHA512() = default;

  // Compute a SHA512 of a memory bufferin one go.
  SHA512(Span<const U8>);

  // Access individual bytes of SHA512.
  U8 &operator[](size_t i) { return bytes[i]; }

  // Builder can be used to compute SHA512 incrementally.
  struct Builder {
    U64 length;
    U64 state[8];
    U32 curlen;
    U8 buf[128];
    Builder();
    Builder &Update(Span<const U8>);
    SHA512 Finalize();
  };

  operator MemView() { return bytes; }
  operator Span<const U8>() const { return bytes; }
};

} // namespace maf
