#pragma once

#include "int.hh"
#include "span.hh"
#include "vec.hh"

namespace maf {

// Class used to construct buffers of data.
struct BufferBuilder {
  Vec<> buffer;

  BufferBuilder() = default;
  BufferBuilder(Size initial_capacity) { buffer.reserve(initial_capacity); }

  template <typename T> void Append(const T &t) {
    Span<> t_span((char *)&t, sizeof(T));
    buffer.insert(buffer.end(), t_span.begin(), t_span.end());
  }

  template <> void Append(const Vec<> &view) {
    buffer.insert(buffer.end(), view.begin(), view.end());
  }

  template <> void Append(const StrView &view) {
    buffer.insert(buffer.end(), view.begin(), view.end());
  }

  template <> void Append(const Span<> &span) {
    buffer.insert(buffer.end(), span.begin(), span.end());
  }

  operator Span<>() { return buffer; }
};

} // namespace maf