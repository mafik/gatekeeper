#include "str.hh"
#include "int.hh"

namespace maf {

// https://stackoverflow.com/questions/3418231/replace-part-of-a-string-with-another-string
void ReplaceAll(Str &s, const Str &from, const Str &to) {
  if (from.empty())
    return;
  size_t start_pos = 0;
  while ((start_pos = s.find(from, start_pos)) != Str::npos) {
    s.replace(start_pos, from.length(), to);
    start_pos += to.length(); // In case 'to' contains 'from', like replacing
                              // 'x' with 'yx'
  }
}

Str Indent(StrView view, int spaces) {
  Str ret;
  while (!view.empty()) {
    Size eol = view.find('\n');
    if (eol == Str::npos) {
      ret += Str(spaces, ' ');
      ret += view;
      break;
    } else if (eol == 0) {
      ret += '\n';
    } else {
      ret += Str(spaces, ' ');
      ret += view.substr(0, eol);
      ret += '\n';
      view.remove_prefix(eol + 1);
    }
  }
  return ret;
}

} // namespace maf
