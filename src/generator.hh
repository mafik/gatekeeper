#pragma once

#include <coroutine>
#include <iterator>
#include <utility>

#include "manual_lifetime.hh"

template <typename Ref, typename Value = std::decay_t<Ref>> class Generator {
public:
  class promise_type {
  public:
    promise_type() noexcept {}

    ~promise_type() noexcept { clear_value(); }

    void clear_value() {
      if (hasValue_) {
        hasValue_ = false;
        ref_.Destruct();
      }
    }

    Generator get_return_object() noexcept {
      return Generator{
          std::coroutine_handle<promise_type>::from_promise(*this)};
    }

    std::suspend_always initial_suspend() noexcept { return {}; }

    std::suspend_always final_suspend() noexcept { return {}; }

    std::suspend_always
    yield_value(Ref ref) noexcept(std::is_nothrow_move_constructible_v<Ref>) {
      auto &&rref = std::move(ref);
      ref_.Construct(rref);
      hasValue_ = true;
      return {};
    }

    void return_void() {}

    void unhandled_exception() { throw; }

    Ref Get() { return ref_.Get(); }

  private:
    ManualLifetime<Ref> ref_;
    bool hasValue_ = false;
  };

  using handle_t = std::coroutine_handle<promise_type>;

  Generator(Generator &&g) noexcept : coro_(std::exchange(g.coro_, {})) {}

  ~Generator() {
    if (coro_) {
      coro_.destroy();
    }
  }

  struct sentinel {};

  class iterator {
  public:
    using reference = Ref;
    using value_type = Value;
    using difference_type = std::ptrdiff_t;
    using pointer = std::add_pointer_t<Ref>;
    using iterator_category = std::input_iterator_tag;

    iterator() noexcept {}

    explicit iterator(handle_t coro) noexcept : coro_(coro) {}

    reference operator*() const { return coro_.promise().Get(); }

    iterator &operator++() {
      coro_.promise().clear_value();
      coro_.resume();
      return *this;
    }

    void operator++(int) {
      coro_.promise().clear_value();
      coro_.resume();
    }

    friend bool operator==(const iterator &it, sentinel) noexcept {
      return it.coro_.done();
    }
    friend bool operator==(sentinel, const iterator &it) noexcept {
      return it.coro_.done();
    }
    friend bool operator!=(const iterator &it, sentinel) noexcept {
      return !it.coro_.done();
    }
    friend bool operator!=(sentinel, const iterator &it) noexcept {
      return !it.coro_.done();
    }

  private:
    handle_t coro_;
  };

  iterator begin() {
    coro_.resume();
    return iterator{coro_};
  }

  sentinel end() { return {}; }

private:
  explicit Generator(handle_t coro) noexcept : coro_(coro) {}

  handle_t coro_;
};