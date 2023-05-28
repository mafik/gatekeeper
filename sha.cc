#include "sha.hh"

#include <openssl/sha.h>

std::string SHA1(std::string_view str) {
  unsigned char sha_sum[SHA_DIGEST_LENGTH];
  ::SHA1((const unsigned char *)str.data(), str.size(), sha_sum);
  return std::string((char *)sha_sum, SHA_DIGEST_LENGTH);
}
