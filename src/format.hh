#pragma once

#include "str.hh"

namespace maf {

// TODO: replace this with std::format when it's available
Str f(const char *fmt, ...);

// Prefix each line with `spaces` spaces.
std::string IndentString(std::string in, int spaces = 2);

std::string Slugify(std::string in);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-security"
constexpr void constexpr_sprintf(std::string &out, const char *format,
                                 auto... args) {
  int n = snprintf(nullptr, 0, format, args...) + 1;
  char buf[n];
  snprintf(buf, n, format, args...);
  out += buf;
}
#pragma clang diagnostic pop

template <typename T> std::string dump_struct(const T &t) {
  std::string s;
  __builtin_dump_struct(&t, constexpr_sprintf, s);
  return s;
}

} // namespace maf