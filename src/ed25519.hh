#pragma once

#include <cstdint>
#include <string_view>
#include <utility>

#include "status.hh"

// Public-key signature system according to http://ed25519.cr.yp.to/.
namespace maf::ed25519 {

struct Private {
  uint8_t bytes[32];

  static Private FromDevUrandom(Status &);
  static Private FromHex(std::string_view, Status &);
};

struct Public {
  uint8_t bytes[32];

  static Public FromPrivate(const Private &);
  static Public FromHex(std::string_view, Status &);
};

struct Signature {
  union {
    uint8_t bytes[64];
    struct {
      uint8_t R[32];
      uint8_t S[32];
    };
  };

  Signature() = default;
  Signature(std::string_view message, const Private &, const Public &);
  static Signature FromHex(std::string_view hex, Status &);
  static Signature FromHexRS(std::string_view R_hex, std::string_view S_hex,
                             Status &);
  bool Verify(std::string_view message, const Public &) const;
};

} // namespace maf::ed25519