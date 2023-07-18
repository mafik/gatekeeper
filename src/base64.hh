#pragma once

#include "str.hh"

namespace maf {

const char kBase64Chars[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                              "abcdefghijklmnopqrstuvwxyz"
                              "0123456789+/";

inline bool IsBase64(int c) { return (isalnum(c) || (c == '+') || (c == '/')); }

Str Base64Encode(StrView buf);

} // namespace maf
