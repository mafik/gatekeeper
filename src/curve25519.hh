#pragma once

#include <cstdint>

#include "arr.hh"
#include "int.hh"
#include "mem.hh"
#include "status.hh"

// Establishing shared secrets according to https://cr.yp.to/ecdh.html.
//
// This is a C++ wrapper around the curve25519-donna C library (public-domain).
namespace maf::curve25519 {

struct Private {
  Arr<U8, 32> bytes;

  static Private From32Bytes(Span<const U8, 32> bytes);
  static Private FromDevUrandom(Status &);

  operator MemView() { return bytes; }
};

struct Public {
  Arr<U8, 32> bytes;

  static Public FromPrivate(const Private &);

  bool operator==(const Public &) const;
  operator MemView() { return bytes; }
};

struct Shared {
  Arr<U8, 32> bytes;

  static Shared FromPrivateAndPublic(const Private &, const Public &);

  operator Span<const U8>() const { return bytes; }
};

} // namespace maf::curve25519