#pragma once

#include <span>

#include "int.hh"
#include "str.hh"

namespace maf {

constexpr Size DynamicExtent = std::dynamic_extent;

// Wrapper around std::span with some quality-of-life improvements.
template <class T = char, Size Extent = DynamicExtent>
struct Span : std::span<T, Extent> {
  using std::span<T, Extent>::span;

  // Allow Span of const arrays.
  inline Span(const T *arr, Size n)
      : std::span<T, Extent>(const_cast<T *>(arr), n) {}
  inline Span(const Str &s) : Span(s.data(), s.size() / sizeof(T)) {}
  inline Span(StrView s) : Span(s.data(), s.size() / sizeof(T)) {}
  inline Span(std::span<T, Extent> s) : std::span<T, Extent>(s) {}

  template <Size ExtentRhs>
  inline Span &operator=(const std::span<T, ExtentRhs> &rhs) {
    std::span<char, Extent>::operator=(rhs);
    return *this;
  }

  void RemovePrefix(Size n) { *this = this->subspan(n); }

  template <Size ExtentRhs>
  constexpr inline bool StartsWith(Span<T, ExtentRhs> prefix) {
    if (this->size() < prefix.size()) {
      return false;
    }
    return std::equal(prefix.begin(), prefix.end(), this->begin());
  }

  template <typename U> U &As() {
    assert(this->size() == sizeof(U));
    return *(U *)this->data();
  }

  Str ToStr() const { return Str(this->data(), this->size() * sizeof(T)); }
};

// Span of a C string, excluding the null terminator.
template <size_t N>
constexpr inline Span<char, N - 1> SpanOf(const char (&c_str)[N]) {
  return Span<char, N - 1>(const_cast<char *>(c_str), N - 1);
}

inline StrView StrViewOf(Span<char> span) {
  return StrView(span.data(), span.size());
}

} // namespace maf
