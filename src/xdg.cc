#include "xdg.hh"

#include "format.hh"
#include "status.hh"

namespace maf::xdg {

void Open(StrView path_or_url, Status &status) {
  static const bool is_xdg_available = []() {
    int ret = system("xdg-open --version>/dev/null 2>&1");
    return ret == 0;
  }();
  if (!is_xdg_available) {
    AppendErrorMessage(status) += "xdg-open is not available";
    return;
  }
  Str xdg_open_cmd = f("xdg-open %*s", path_or_url.size(), path_or_url.data());
  if (auto sudo_user = getenv("SUDO_USER")) {
    if (auto sudo_uid = getenv("SUDO_UID")) {
      xdg_open_cmd =
          f("sudo -u %s DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%s/bus %s",
            sudo_user, sudo_uid, xdg_open_cmd.c_str());
    } else {
      xdg_open_cmd = f("sudo -u %s %s", sudo_user, xdg_open_cmd.c_str());
    }
  }
  system(xdg_open_cmd.c_str());
}

} // namespace maf::xdg