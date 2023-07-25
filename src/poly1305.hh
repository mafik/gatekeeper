#pragma once

#include "int.hh"
#include "span.hh"

namespace maf {

struct Poly1305 {
  constexpr static size_t kBlockSize = 16;

  U8 bytes[16];

  // Construct an uninitialized Poly1305.
  Poly1305() = default;

  Poly1305(Span<const U8, 16> buffer);

  // Compute a Poly1305 of a memory buffer in one go.
  Poly1305(Span<const U8> m, Span<const U8, 32> key);

  struct Builder {
    unsigned long long r[3];
    unsigned long long h[3];
    unsigned long long pad[2];
    size_t leftover;
    unsigned char buffer[kBlockSize];
    unsigned char final;

    Builder(Span<const U8, 32> key);
    Builder &Update(Span<const U8>);
    Poly1305 Finalize();
  };

  operator Span<const U8>() const { return bytes; }
};

} // namespace maf