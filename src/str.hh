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

} // namespace maf
