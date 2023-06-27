#pragma once

#include <string>
#include <string_view>

std::string SHA1(std::string_view str);

struct SHA512 {
  uint8_t bytes[64];

  // Construct an uninitialized SHA512. There shoud be no reason to use this
  // function except to reserve space for a proper SHA512.
  SHA512() = default;

  // Compute a SHA512 of a `string_view`.
  SHA512(std::string_view);

  // Compute a SHA512 from a range of bytes.
  SHA512(const uint8_t *bytes, size_t len)
      : SHA512(std::string_view((const char *)bytes, len)) {}

  // Access individual bytes of SHA512.
  uint8_t &operator[](size_t i) { return bytes[i]; }

  // Builder can be used to compute SHA512 incrementally.
  struct Builder {
    uint64_t length;
    uint64_t state[8];
    uint32_t curlen;
    uint8_t buf[128];
    Builder();
    Builder &Update(std::string_view);
    Builder &Update(const uint8_t *bytes, size_t len) {
      return Update(std::string_view((const char *)bytes, len));
    }
    SHA512 Finalize();
  };
};
