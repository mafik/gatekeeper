#pragma once

#include <string>

// printf-like formatting function.
// TODO: replace this with std::format when it's available
std::string f(const char *fmt, ...);

// Prefix each line with `spaces` spaces.
std::string IndentString(std::string in, int spaces = 2);

std::string Slugify(std::string in);