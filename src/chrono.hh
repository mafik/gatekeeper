#pragma once

// Utilities for working with std::chrono.

#include "str.hh"
#include <chrono>
#include <optional>

namespace maf {
Str FormatDuration(std::optional<std::chrono::steady_clock::duration> d_opt,
                   const char *never = "∞");

}; // namespace maf