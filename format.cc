#include "format.hh"

#include <cstdio>
#include <stdarg.h>

std::string f(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  va_list args2;
  va_copy(args2, args);
  int n = vsnprintf(NULL, 0, fmt, args) + 1;
  char buf[n];
  vsnprintf(buf, sizeof(buf), fmt, args2);
  va_end(args);
  return std::string(buf);
}

std::string IndentString(std::string in, int spaces) {
  std::string out(spaces, ' ');
  for (char c : in) {
    out += c;
    if (c == '\n') {
      for (int i = 0; i < spaces; ++i) {
        out += ' ';
      }
    }
  }
  return out;
}
