#pragma once

#include <cstdint>

#include "status.hh"

// Establishing shared secrets according to https://cr.yp.to/ecdh.html.
//
// This is a C++ wrapper around the curve25519-donna C library (public-domain).
namespace maf::curve25519 {

struct Private {
  uint8_t bytes[32];

  static Private FromDevUrandom(Status &);
};

struct Public {
  uint8_t bytes[32];

  static Public FromPrivate(const Private &);
};

struct Shared {
  uint8_t bytes[32];

  static Shared FromPrivateAndPublic(const Private &, const Public &);
};

} // namespace maf::curve25519