#include "base64.hh"

static const unsigned char kBase64Chars[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64Encode(std::string_view in) {
  const int out_size = (in.size() + 2) / 3 * 4;
  char out_buf[out_size];
  char *p = out_buf;
  const uint8_t *src = (const uint8_t *)in.data();
  int len = in.size();
  while (len >= 3) { // there are at least 3 characters to encode
    uint32_t x = (src[0] << 16) | (src[1] << 8) | src[2];
    *p++ = kBase64Chars[(x >> 18) & 0x3f];
    *p++ = kBase64Chars[(x >> 12) & 0x3f];
    *p++ = kBase64Chars[(x >> 6) & 0x3f];
    *p++ = kBase64Chars[x & 0x3f];
    len -= 3;
    src += 3;
  }
  if (len == 1) { // there is only one character to encode
    uint32_t x = src[0] << 16;
    *p++ = kBase64Chars[(x >> 18) & 0x3f];
    *p++ = kBase64Chars[(x >> 12) & 0x3f];
    *p++ = '=';
    *p++ = '=';
  } else if (len == 2) { // there are two characters to encode
    uint32_t x = (src[0] << 16) | (src[1] << 8);
    *p++ = kBase64Chars[(x >> 18) & 0x3f];
    *p++ = kBase64Chars[(x >> 12) & 0x3f];
    *p++ = kBase64Chars[(x >> 6) & 0x3f];
    *p++ = '=';
  }
  return std::string(out_buf, out_size);
}
