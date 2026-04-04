#pragma once

#include "str.hh"
#include "vec.hh"

namespace automat {

Vec<StrView> SplitOnChars(StrView s, StrView chars);

} // namespace automat
