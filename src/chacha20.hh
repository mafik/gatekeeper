#pragma once

#include "arr.hh"
#include "int.hh"
#include "mem.hh"
#include "span.hh"

namespace maf {

// RFC 7539 altered the original ChaCha20 specification to use a 96-bit nonce.
// It is kept in a separate namespace so that if 64-bit nonce is ever needed
// (for expamle for SSH compatiblity), it can be made available in another
// namespace.
namespace rfc7539 {

struct ChaCha20 {
  Arr<U8, 16> constant;
  Arr<U8, 32> key;
  U32 counter;
  Arr<U8, 12> nonce;

  ChaCha20(Span<const U8, 32> key, U32 counter, Span<const U8, 12> nonce);

  // Encrypt/decrypt the given buffer in-place.
  //
  // `counter` will be updated by the number of blocks encrypted.
  void Crypt(MemView);

  operator Span<const U8>() const {
    return Span<const U8>((const U8 *)this, sizeof(*this));
  }
};

} // namespace rfc7539

using ChaCha20 = rfc7539::ChaCha20;

} // namespace maf