#include "split.hh"

#include "int.hh"

namespace maf {

Vec<StrView> SplitOnChars(StrView s, StrView chars) {
  Vec<StrView> result;
  Size begin = 0;
  Size end = s.find_first_of(chars, begin);
  while (end != StrView::npos) {
    result.push_back(s.substr(begin, end - begin));
    begin = end + 1;
    if (begin >= s.size()) {
      break;
    }
    end = s.find_first_of(chars, begin);
  }
  if (begin < s.size()) {
    result.push_back(s.substr(begin, s.size() - begin));
  } else if (begin == s.size()) { // If the last character was a separator.
    result.push_back(StrView{});
  }
  return result;
}

} // namespace maf