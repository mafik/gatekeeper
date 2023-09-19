#include "base64.hh"

#include "int.hh"

namespace maf {

Str Base64Encode(Span<> buf) {
  Str ret;
  int i = 0;
  int j = 0;
  U8 char_array_3[3];
  U8 char_array_4[4];

  while (!buf.empty()) {
    char_array_3[i++] = buf.front();
    buf.RemovePrefix(1);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] =
          ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] =
          ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for (i = 0; (i < 4); i++)
        ret += kBase64Chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i) {
    for (j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] =
        ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] =
        ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += kBase64Chars[char_array_4[j]];

    while ((i++ < 3))
      ret += '=';
  }

  return ret;
}

#pragma maf add compile argument "-Wno-c99-designator";

constexpr static std::array<U8, 256> kBase64Index = []() {
  std::array<U8, 256> arr{};
  for (int i = 0; i < 64; ++i) {
    arr[kBase64Chars[i]] = i;
  }
  return arr;
}();

Vec<> Base64Decode(StrView encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  U8 char_array_4[4], char_array_3[3];
  Vec<> ret;

  while (in_len-- && (encoded_string[in_] != '=')) {
    if (not IsBase64(encoded_string[in_])) {
      ++in_;
      continue;
    }

    char_array_4[i++] = encoded_string[in_++];
    if (i == 4) {
      for (i = 0; i < 4; i++)
        char_array_4[i] = kBase64Index[char_array_4[i]];

      char_array_3[0] =
          (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] =
          ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret.push_back(char_array_3[i]);
      i = 0;
    }
  }

  if (i) {
    for (j = i; j < 4; j++)
      char_array_4[j] = 0;

    for (j = 0; j < 4; j++)
      char_array_4[j] = kBase64Index[char_array_4[j]];

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] =
        ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++)
      ret.push_back(char_array_3[j]);
  }

  return ret;
}

} // namespace maf
