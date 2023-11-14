#include "passgen.hh"

#include "arr.hh"
#include "random.hh"
#include "span.hh"

namespace maf {

static const auto kASCIIPasswordChars = "abcdefghijklmnopqrstuvwxyz"
                                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                        "0123456789"
                                        "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"sv;

Str RandomPassword52bit() {
  U64 random_bytes;
  RandomBytesSecure(SpanOfRef(random_bytes));
  Str password;
  for (int i = 0; i < 8; ++i) {
    password += kASCIIPasswordChars[random_bytes % kASCIIPasswordChars.size()];
    random_bytes /= kASCIIPasswordChars.size();
  }
  return password;
}

} // namespace maf