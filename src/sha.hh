#pragma once

#include "int.hh"
#include "span.hh"
#include "str.hh"

namespace maf {

struct SHA1 {
  char bytes[20];

  SHA1(Span<>);

  operator Span<char, 20>() { return bytes; }
  operator Span<>() { return bytes; }
  // TODO: SHA1 is not text so this operator should be removed
  operator StrView() { return StrView(bytes, 20); }
};

struct SHA256 {
  constexpr static size_t kBlockSize = 64;

  char bytes[32];

  // Construct an uninitialized SHA256. There shoud be no reason to use this
  // function except to reserve space for a proper SHA256.
  SHA256() = default;

  // Compute a SHA256 of a memory buffer in one go.
  SHA256(Span<>);

  struct Builder {
    U32 state[8];
    U8 buffer[64];
    U64 n_bits;
    U8 buffer_counter;
    Builder();
    Builder &Update(Span<>);
    SHA256 Finalize();
  };

  operator Span<char, 32>() { return bytes; }
  operator Span<>() { return bytes; }
};

struct SHA512 {
  char bytes[64];

  // Construct an uninitialized SHA512. There shoud be no reason to use this
  // function except to reserve space for a proper SHA512.
  SHA512() = default;

  // Compute a SHA512 of a memory bufferin one go.
  SHA512(Span<>);

  // Access individual bytes of SHA512.
  char &operator[](size_t i) { return bytes[i]; }

  // Builder can be used to compute SHA512 incrementally.
  struct Builder {
    U64 length;
    U64 state[8];
    U32 curlen;
    U8 buf[128];
    Builder();
    Builder &Update(Span<>);
    SHA512 Finalize();
  };

  operator Span<char, 64>() { return bytes; }
  operator Span<>() { return bytes; }
};

} // namespace maf
