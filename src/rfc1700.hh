#pragma once

#include <cstdint>
#include <string>

namespace rfc1700 {

extern const char *kHardwareTypeNames[22];

std::string HardwareTypeToString(uint8_t type);

} // namespace rfc1700