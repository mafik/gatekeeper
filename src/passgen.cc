#include "passgen.hh"

#include "arr.hh"
#include "random.hh"
#include "span.hh"
#include "split.hh"
#include "virtual_fs.hh"

#include <algorithm>
#include <cctype>
#include <iterator>

namespace maf {

static const auto kASCIIPasswordChars = "abcdefghijklmnopqrstuvwxyz"
                                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                        "0123456789"
                                        "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"sv;

static const auto kSeparators = "!#$%&-_.,;:|+*~"sv;

Str RandomPassword52bit() {
  Str password;
  U64 randomness;
  RandomBytesSecure(SpanOfRef(randomness));
  Status status;
  double entropy = 0;
  fs::Map(
      fs::real, "/usr/share/dict/words",
      [&](StrView words) {
        auto words_vec = SplitOnChars(words, "\n"sv);
        std::erase_if(words_vec, [](StrView word) {
          return (word.size() < 3) || (word.size() > 9) ||
                 !std::ranges::all_of(word, [](char c) { return isalpha(c); });
        });
        char separator = kSeparators[randomness % kSeparators.size()];
        randomness /= kSeparators.size();
        entropy += log2(kSeparators.size());
        for (int i = 0; i < 3; ++i) {
          if (i) {
            password += separator;
          }
          StrView word = words_vec[randomness % words_vec.size()];
          bool uppercase = randomness % 2;
          randomness /= 2;
          entropy += 1;
          std::ranges::transform(
              word, std::back_inserter(password),
              uppercase ? [](char c) { return toupper(c); }
                        : [](char c) { return tolower(c); });

          randomness /= words_vec.size();
          entropy += log2(words_vec.size());
        }
      },
      status);
  if (entropy < 52) {
    password.clear();
    for (int i = 0; i < 8; ++i) {
      password += kASCIIPasswordChars[randomness % kASCIIPasswordChars.size()];
      randomness /= kASCIIPasswordChars.size();
    }
  }
  return password;
}

} // namespace maf