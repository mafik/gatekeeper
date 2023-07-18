#pragma once

#include <string>

namespace maf {

using Str = std::string;
using StrView = std::string_view;

using namespace std::literals;

void ReplaceAll(Str &s, const Str &from, const Str &to);

} // namespace maf
