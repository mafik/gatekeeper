#pragma once

#include "int.hh"
#include "span.hh"

namespace maf {

struct Poly1305 {
  constexpr static size_t kBlockSize = 16;

  char bytes[16];

  // Construct an uninitialized Poly1305.
  Poly1305() = default;

  Poly1305(Span<char, 16> buffer);

  // Compute a Poly1305 of a memory buffer in one go.
  Poly1305(Span<> m, Span<char, 32> key);

  struct Builder {
    unsigned long long r[3];
    unsigned long long h[3];
    unsigned long long pad[2];
    size_t leftover;
    char buffer[kBlockSize];
    unsigned char final;

    Builder(Span<char, 32> key);
    Builder &Update(Span<>);
    Poly1305 Finalize();
  };

  operator Span<>() const { return Span<>(bytes, 16); }
};

} // namespace maf