#pragma once

#include "hmac.hh"
#include "mem.hh"

namespace maf {

template <typename Hash>
Hash HKDF_Extract(Span<const U8> salt, Span<const U8> ikm) {
  return HMAC<Hash>(salt, ikm);
}

template <typename Hash>
void HKDF_Expand(MemView prk, MemView info, MemView out) {
  U8 i = 0;
  MemBuf t;
  size_t filled = 0;
  while (filled < out.size()) {
    ++i;
    t.insert(t.end(), info.begin(), info.end());
    t.push_back(i);
    Hash hmac = HMAC<Hash>(prk, t);
    t.assign(hmac.bytes, hmac.bytes + sizeof(hmac.bytes));
    size_t n = std::min(out.size() - filled, sizeof(Hash));
    memcpy(out.data() + filled, hmac.bytes, n);
    filled += n;
  }
}

template <typename Hash>
MemBuf HKDF(MemView salt, MemView ikm, MemView info, Size len) {
  Hash prk = HKDF_Extract<Hash>(salt, ikm);
  MemBuf out(len);
  HKDF_Expand<Hash>(prk, info, out);
  return out;
}

} // namespace maf