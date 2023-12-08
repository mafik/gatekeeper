#include "chrono.hh"

using namespace std;
using namespace std::chrono;

namespace maf {

string FormatDuration(optional<steady_clock::duration> d_opt,
                      const char *never) {
  if (!d_opt) {
    return never;
  }
  steady_clock::duration &d = *d_opt;
  string r;
  auto h = duration_cast<chrono::hours>(d);
  d -= h;
  if (h.count() != 0) {
    r += ToStr(h.count()) + "h";
  }
  auto m = duration_cast<chrono::minutes>(d);
  d -= m;
  if (m.count() != 0) {
    if (!r.empty()) {
      r += " ";
    }
    r += ToStr(m.count()) + "m";
  }
  auto s = duration_cast<chrono::seconds>(d);
  d -= s;
  if (r.empty() || (s.count() != 0)) {
    if (!r.empty()) {
      r += " ";
    }
    r += ToStr(s.count()) + "s";
  }
  return r;
}

} // namespace maf