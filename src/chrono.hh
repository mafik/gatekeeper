#pragma once

// Utilities for working with std::chrono.

#include <chrono>
#include <optional>
#include <string>

std::string
FormatDuration(std::optional<std::chrono::steady_clock::duration> d_opt,
               const char *never = "∞");