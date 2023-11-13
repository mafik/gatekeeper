#pragma once

#include "int.hh"
#include "span.hh"

namespace maf {

struct AES {
  U32 eK[60];
  U32 dK[60];
  U32 Nr;

  AES(Span<char, 16>);
  AES(Span<char, 24>);
  AES(Span<char, 32>);

  void Encrypt(Span<char, 16>);
  void Decrypt(Span<char, 16>);

  // Key wrapping according to RFC 3394.
  //
  // Wrapping is performed in-place. The returned value is the 64-bit IV which
  // should be used as a prefix to the wrapped key.
  U64 WrapKey(Span<U64> key);
};

} // namespace maf