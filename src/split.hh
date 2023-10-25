#pragma once

#include "str.hh"
#include "vec.hh"

namespace maf {

Vec<StrView> SplitOnChars(StrView s, StrView chars);

} // namespace maf
