#pragma once

#include "hmac.hh"
#include "span.hh"
#include "vec.hh"

namespace maf {

template <typename Hash> Hash HKDF_Extract(Span<> salt, Span<> ikm) {
  return HMAC<Hash>(salt, ikm);
}

template <typename Hash> void HKDF_Expand(Span<> prk, Span<> info, Span<> out) {
  U8 i = 0;
  Vec<> t;
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
Vec<> HKDF(Span<> salt, Span<> ikm, Span<> info, Size len) {
  Hash prk = HKDF_Extract<Hash>(salt, ikm);
  Vec<> out(len);
  HKDF_Expand<Hash>(prk, info, out);
  return out;
}

} // namespace maf