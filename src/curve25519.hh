#pragma once

#include "arr.hh"
#include "span.hh"
#include "status.hh"

// Establishing shared secrets according to https://cr.yp.to/ecdh.html.
//
// This is a C++ wrapper around the curve25519-donna C library (public-domain).
namespace maf::curve25519 {

struct Private {
  Arr<char, 32> bytes;

  static Private From32Bytes(Span<char, 32> bytes);
  static Private FromDevUrandom(Status &);

  operator Span<>() { return bytes; }
};

struct Public {
  Arr<char, 32> bytes;

  static Public FromPrivate(const Private &);

  bool operator==(const Public &) const;
  operator Span<>() { return bytes; }
};

struct Shared {
  Arr<char, 32> bytes;

  static Shared FromPrivateAndPublic(const Private &, const Public &);

  operator Span<>() { return bytes; }
};

} // namespace maf::curve25519