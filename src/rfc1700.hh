#pragma once

#include "int.hh"
#include "str.hh"

namespace maf::rfc1700 {

extern const char *kHardwareTypeNames[22];

Str HardwareTypeToStr(U8 type);

} // namespace maf::rfc1700