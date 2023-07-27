#include "sig.hh"

#include "arr.hh"

#pragma maf add link argument "-Wl,--script=src/sig.x"

namespace maf {

// Reserve space for signature. Actual signing happens after linking.
__attribute__((section("maf.sig.ed25519"))) __attribute__((used))
const ed25519::Signature kSignature = {};

} // namespace maf