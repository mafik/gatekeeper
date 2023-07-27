#pragma once

#include "poly1305.hh"
#include "span.hh"

namespace maf {

Poly1305 Encrypt_AEAD_CHACHA20_POLY1305(Span<char, 32> key,
                                        Span<char, 12> nonce, Span<> data,
                                        Span<> aad);

bool Decrypt_AEAD_CHACHA20_POLY1305(Span<char, 32> key, Span<char, 12> nonce,
                                    Span<> data, Span<> aad,
                                    const Poly1305 &tag);

} // namespace maf