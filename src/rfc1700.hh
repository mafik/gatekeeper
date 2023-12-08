#pragma once

#include <cstdint>

#include "str.hh"

namespace rfc1700 {

extern const char *kHardwareTypeNames[22];

maf::Str HardwareTypeToStr(uint8_t type);

} // namespace rfc1700