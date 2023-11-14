#pragma once

#include "str.hh"

namespace maf {

// Pick a random password with approximately 52 bits of entropy.
//
// If /usr/share/dict/words exists, it will be used to make the password easier
// to remember.
Str RandomPassword52bit();

} // namespace maf