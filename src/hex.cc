#include "hex.hh"

std::string hex(const void *ptr, size_t size) {
  std::string result;
  result.reserve(size * 2);
  for (size_t i = 0; i < size; i++) {
    char buf[3];
    sprintf(buf, "%02x", ((uint8_t *)ptr)[i]);
    result += buf;
  }
  return result;
}
