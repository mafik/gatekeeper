#pragma once

#include "int.hh"
#include "span.hh"
#include "vec.hh"

namespace maf {

// Class used to construct buffers of data.
struct BufferBuilder {
  Vec<> buffer;

  template <typename T> struct Ref {
    BufferBuilder &builder;
    Size offset;
    T &operator*() { return *(T *)(builder.buffer.data() + offset); }
    T *operator->() { return (T *)(builder.buffer.data() + offset); }
    operator T &() { return *(T *)(builder.buffer.data() + offset); }
  };

  BufferBuilder() = default;
  BufferBuilder(Size initial_capacity) { buffer.reserve(initial_capacity); }

  template <typename T> Ref<T> AppendPrimitive(const T &t) {
    Ref<T> ref{
        .builder = *this,
        .offset = buffer.size(),
    };
    Span<> t_span((char *)&t, sizeof(T));
    buffer.insert(buffer.end(), t_span.begin(), t_span.end());
    return ref;
  }

  template <typename T>
  Ref<typename T::value_type> AppendRange(const T &range) {
    Ref<typename T::value_type> ref{
        .builder = *this,
        .offset = buffer.size(),
    };
    for (auto &e : range) {
      AppendPrimitive(e);
    }
    return ref;
  }

  void AppendZeroes(Size n) { buffer.insert(buffer.end(), n, 0); }

  // Aligns the buffer to the given alignment.
  //
  // The alignment must be a power of two.
  template <U8 alignment> void AlignTo() {
    // Verify that the alignment is a power of two.
    static_assert((alignment & (alignment - 1)) == 0);
    if (buffer.size() & (alignment - 1)) {
      buffer.resize((buffer.size() + alignment - 1) & ~(alignment - 1));
    }
  }

  operator Span<>() { return buffer; }

  Size Size() const { return buffer.size(); }
};

} // namespace maf