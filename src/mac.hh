#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

struct MAC {
  uint8_t bytes[6];
  MAC() : bytes{0, 0, 0, 0, 0, 0} {}
  MAC(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f)
      : bytes{a, b, c, d, e, f} {}
  MAC(char s[6])
      : bytes{(uint8_t)s[0], (uint8_t)s[1], (uint8_t)s[2],
              (uint8_t)s[3], (uint8_t)s[4], (uint8_t)s[5]} {}
  static MAC FromInterface(std::string_view interface_name);
  std::string to_string() const;
  uint8_t &operator[](int i) { return bytes[i]; }
  bool TryParse(const char *cp) {
    return sscanf(cp, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &bytes[0], &bytes[1],
                  &bytes[2], &bytes[3], &bytes[4], &bytes[5]) == 6;
  }
  auto operator<=>(const MAC &other) const = default;
  enum CastType { CAST_MULTICAST, CAST_UNICAST };
  CastType cast_type() const {
    if (bytes[0] & 0x01) {
      return CAST_MULTICAST;
    } else {
      return CAST_UNICAST;
    }
  }
  bool IsGloballyUnique() const { return (bytes[0] & 0x02) == 0; }
};

template <> struct std::hash<MAC> {
  std::size_t operator()(const MAC &mac) const {
    return std::hash<uint64_t>()((uint64_t)mac.bytes[5] << 40 |
                                 (uint64_t)mac.bytes[4] << 32 |
                                 mac.bytes[3] << 24 | mac.bytes[2] << 16 |
                                 mac.bytes[1] << 8 | mac.bytes[0]);
  }
};