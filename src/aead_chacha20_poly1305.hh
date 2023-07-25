#pragma once

#include "int.hh"
#include "poly1305.hh"
#include "span.hh"

namespace maf {

Poly1305 Encrypt_AEAD_CHACHA20_POLY1305(Span<const U8, 32> key,
                                        Span<const U8, 12> nonce, Span<U8> data,
                                        Span<const U8> aad);

bool Decrypt_AEAD_CHACHA20_POLY1305(Span<const U8, 32> key,
                                    Span<const U8, 12> nonce, Span<U8> data,
                                    Span<const U8> aad, const Poly1305 &tag);

} // namespace maf