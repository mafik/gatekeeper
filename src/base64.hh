#pragma once

#include "span.hh"
#include "str.hh"
#include "vec.hh"

namespace maf {

constexpr char kBase64Chars[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                  "abcdefghijklmnopqrstuvwxyz"
                                  "0123456789+/";

inline bool IsBase64(int c) { return (isalnum(c) || (c == '+') || (c == '/')); }

Str Base64Encode(Span<> buf);
Vec<> Base64Decode(StrView buf);

} // namespace maf
