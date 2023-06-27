#pragma once

#include <string>

std::string hex(const void *ptr, size_t size);

namespace maf {

void HexToBytesUnchecked(std::string_view hex, uint8_t *bytes);

} // namespace maf