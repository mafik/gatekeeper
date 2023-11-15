#pragma once

#include <memory>

template <typename T> struct ManualLifetime {
public:
  ManualLifetime() noexcept {}
  ~ManualLifetime() noexcept {}

  template <typename... Args> void Construct(Args &&...args) {
    ::new (static_cast<void *>(std::addressof(value)))
        T(static_cast<Args &&>(args)...);
  }

  void Destruct() { value.~T(); }

  T &Get() & { return value; }
  const T &Get() const & { return value; }
  T &&Get() && { return (T &&)value; }
  const T &&Get() const && { return (const T &&)value; }

private:
  union {
    T value;
  };
};

template <typename T> struct ManualLifetime<T &> {
  ManualLifetime() noexcept : ptr(nullptr) {}
  ~ManualLifetime() {}

  void Construct(T &value) noexcept { ptr = std::addressof(value); }
  void Destruct() noexcept { ptr = nullptr; }

  T &Get() const noexcept { return *ptr; }

private:
  T *ptr;
};

template <typename T> struct ManualLifetime<T &&> {
  ManualLifetime() noexcept : ptr(nullptr) {}
  ~ManualLifetime() {}

  void Construct(T &&value) noexcept { ptr = std::addressof(value); }
  void Destruct() noexcept { ptr = nullptr; }

  T &&Get() const noexcept { return *ptr; }

private:
  T *ptr;
};

template <> struct ManualLifetime<void> {
  void Construct() noexcept {}
  void Destruct() noexcept {}
  void Get() const noexcept {}
};
