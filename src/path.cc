#include "path.hh"

#include <pwd.h>

namespace maf {

Path Path::ExpandUser() const {
  StrView p = str;
  if (p.starts_with("~")) {
    p.remove_prefix(1);
    if (p.empty() or p.starts_with("/")) {
      return Path(getenv("HOME") + Str(p));
    } else {
      size_t slash_pos = p.find("/");
      Str username;
      if (slash_pos == StrView::npos) {
        username = p;
      } else {
        username = p.substr(0, slash_pos);
      }
      struct passwd *pw = getpwnam(username.c_str());
      return Str(pw->pw_dir) + Str(p.substr(slash_pos));
    }
  } else {
    return *this;
  }
}

} // namespace maf