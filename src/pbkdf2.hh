#pragma once

#include "big_endian.hh"
#include "buffer_builder.hh"
#include "hmac.hh"
#include "span.hh"
#include <netinet/in.h>

namespace maf {

template <typename Hash>
void PBKDF2(Span<> out, Span<> password, Span<> salt, U32 iterations) {
  const int byte_length = out.size();
  int block_count = (byte_length + sizeof(Hash) - 1) / sizeof(Hash);
  BufferBuilder salt_with_index(salt.size() + 4);
  salt_with_index.AppendRange(salt);
  auto index_ref = salt_with_index.AppendPrimitive<Big<U32>>(0);
  for (int block = 0; block < block_count; ++block) {
    index_ref->Set(block + 1);
    Hash last_prf = HMAC<Hash>(password, salt_with_index);
    for (int k = 0; k < sizeof(Hash); ++k) {
      out[block * sizeof(Hash) + k] = last_prf.bytes[k];
    }
    for (int j = 1; j < iterations; ++j) {
      last_prf = HMAC<Hash>(password, last_prf);
      for (int k = 0; k < sizeof(Hash); ++k) {
        out[block * sizeof(Hash) + k] ^= last_prf.bytes[k];
      }
    }
  }
}

} // namespace maf