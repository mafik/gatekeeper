#pragma once

#include "status.hh"

// Public-key signature system according to http://ed25519.cr.yp.to/.
namespace maf::ed25519 {

struct Private {
  char bytes[32];

  static Private FromDevUrandom(Status &);
  static Private FromHex(StrView, Status &);
};

struct Public {
  char bytes[32];

  static Public FromPrivate(const Private &);
  static Public FromHex(StrView, Status &);
};

struct Signature {
  union {
    char bytes[64];
    struct {
      char R[32];
      char S[32];
    };
  };

  Signature() = default;
  Signature(StrView message, const Private &, const Public &);
  static Signature FromHex(StrView hex, Status &);
  static Signature FromHexRS(StrView R_hex, StrView S_hex, Status &);
  bool Verify(StrView message, const Public &) const;
};

} // namespace maf::ed25519