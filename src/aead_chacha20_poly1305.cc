#include "aead_chacha20_poly1305.hh"

#include "chacha20.hh"
#include "int.hh"
#include "poly1305.hh"

#include <strings.h>

namespace maf {

Poly1305 Encrypt_AEAD_CHACHA20_POLY1305(Span<char, 32> key,
                                        Span<char, 12> nonce, Span<> data,
                                        Span<> aad) {
  char poly1305_key[32] = {};
  ChaCha20 chacha20(key, 0, nonce);
  chacha20.Crypt(poly1305_key);
  chacha20.Crypt(data);

  Poly1305::Builder poly1305_builder(poly1305_key);
  poly1305_builder.Update(aad);
  if (aad.size() & 15) {
    int padding1_size = 16 - (aad.size() & 15);
    char padding1[15] = {};
    poly1305_builder.Update(Span<>(padding1, padding1_size));
  }
  poly1305_builder.Update(data);
  if (data.size() & 15) {
    int padding2_size = 16 - (data.size() & 15);
    char padding2[15] = {};
    poly1305_builder.Update(Span<>(padding2, padding2_size));
  }
  U64 aad_size = aad.size();
  poly1305_builder.Update(Span<>((char *)&aad_size, 8));
  U64 data_size = data.size();
  poly1305_builder.Update(Span<>((char *)&data_size, 8));
  return poly1305_builder.Finalize();
}

bool Decrypt_AEAD_CHACHA20_POLY1305(Span<char, 32> key, Span<char, 12> nonce,
                                    Span<> data, Span<> aad,
                                    const Poly1305 &tag) {
  char poly1305_key[32] = {};
  ChaCha20 chacha20(key, 0, nonce);
  chacha20.Crypt(poly1305_key);
  Poly1305::Builder poly1305_builder(poly1305_key);
  poly1305_builder.Update(aad);
  if (aad.size() & 15) {
    int padding1_size = 16 - (aad.size() & 15);
    char padding1[15] = {};
    poly1305_builder.Update(Span<>(padding1, padding1_size));
  }
  poly1305_builder.Update(data);
  if (data.size() & 15) {
    int padding2_size = 16 - (data.size() & 15);
    char padding2[15] = {};
    poly1305_builder.Update(Span<>(padding2, padding2_size));
  }
  U64 aad_size = aad.size();
  poly1305_builder.Update(Span<>((char *)&aad_size, 8));
  U64 data_size = data.size();
  poly1305_builder.Update(Span<>((char *)&data_size, 8));
  Poly1305 my_tag = poly1305_builder.Finalize();

  if (bcmp(my_tag.bytes, tag.bytes, 16) != 0) {
    return false;
  }
  chacha20.Crypt(data);
  return true;
}

} // namespace maf