#pragma once

#include <string>

namespace maf {

using Str = std::string;
using StrView = std::string_view;

using namespace std::literals;

void ReplaceAll(Str &s, const Str &from, const Str &to);
void StripLeadingWhitespace(Str &);
void StripTrailingWhitespace(Str &);
void StripWhitespace(Str &);
Str Indent(StrView, int spaces = 2);

inline Str ToStr(int x) { return std::to_string(x); }
inline Str ToStr(long x) { return std::to_string(x); }
inline Str ToStr(long long x) { return std::to_string(x); }
inline Str ToStr(unsigned x) { return std::to_string(x); }
inline Str ToStr(unsigned long x) { return std::to_string(x); }
inline Str ToStr(unsigned long long x) { return std::to_string(x); }
inline Str ToStr(float x) { return std::to_string(x); }
inline Str ToStr(double x) { return std::to_string(x); }
inline Str ToStr(long double x) { return std::to_string(x); }

template <typename T>
  requires requires(T t) {
    { t.ToStr() } -> std::same_as<Str>;
  }
Str ToStr(const T &t) {
  return t.ToStr();
}

template <typename T>
concept Stringer = requires(T t) {
  { ToStr(t) } -> std::same_as<Str>;
};

} // namespace maf
