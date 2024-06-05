#pragma once

#include <cstring>
#include <unordered_set>

#include "int.hh"
#include "str.hh"

namespace maf {

struct MAC {
  U8 bytes[6];
  MAC() : bytes{0, 0, 0, 0, 0, 0} {}
  MAC(const MAC &) = default;
  MAC(MAC &&other)
      : bytes{other.bytes[0], other.bytes[1], other.bytes[2],
              other.bytes[3], other.bytes[4], other.bytes[5]} {}
  MAC(U8 a, U8 b, U8 c, U8 d, U8 e, U8 f) : bytes{a, b, c, d, e, f} {}
  MAC(char s[6])
      : bytes{(U8)s[0], (U8)s[1], (U8)s[2], (U8)s[3], (U8)s[4], (U8)s[5]} {}
  MAC &operator=(const MAC &) = default;
  static MAC FromInterface(StrView interface_name);
  static MAC Broadcast() { return MAC(0xff, 0xff, 0xff, 0xff, 0xff, 0xff); }
  Str ToStr() const;
  U8 &operator[](int i) { return bytes[i]; }
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

} // namespace maf

template <> struct std::hash<maf::MAC> {
  std::size_t operator()(const maf::MAC &mac) const {
    return std::hash<maf::U64>()((maf::U64)mac.bytes[5] << 40 |
                                 (maf::U64)mac.bytes[4] << 32 |
                                 mac.bytes[3] << 24 | mac.bytes[2] << 16 |
                                 mac.bytes[1] << 8 | mac.bytes[0]);
  }
};

namespace maf {

// Mixin class for objects that should be indexed by MAC address.
template <typename T> struct HashableByMAC {
  MAC mac;

  HashableByMAC(MAC mac) : mac(mac) {
    assert(by_mac.find((T *)this) == by_mac.end());
    by_mac.insert((T *)this);
  }

  virtual ~HashableByMAC() { by_mac.erase((T *)this); }

  struct HashByMAC {
    using is_transparent = std::true_type;
    size_t operator()(const T *t) const { return std::hash<MAC>()(t->mac); }
    size_t operator()(const MAC &mac) const { return std::hash<MAC>()(mac); }
  };

  struct EqualMAC {
    using is_transparent = std::true_type;
    bool operator()(const T *a, const T *b) const { return a->mac == b->mac; }
    bool operator()(const T *a, const MAC &b) const { return a->mac == b; }
    bool operator()(const MAC &a, const T *b) const { return a == b->mac; }
  };

  static inline std::unordered_set<T *, HashByMAC, EqualMAC> by_mac;

  static T *Find(MAC mac) {
    auto it = by_mac.find(mac);
    if (it == by_mac.end())
      return nullptr;
    return *it;
  }
};

} // namespace maf