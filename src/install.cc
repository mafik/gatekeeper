#include "install.hh"

#include <sys/stat.h>

#include "config.hh"
#include "dhcp.hh"
#include "dns_client.hh"
#include "dns_server.hh"
#include "firewall.hh"
#include "gatekeeper.hh"
#include "status.hh"
#include "systemd.hh"
#include "update.hh"
#include "virtual_fs.hh"
#include "webui.hh"

using namespace maf;

namespace gatekeeper::install {

bool CanInstall() {
  return not systemd::IsRunningUnderSystemd() && systemd::IsSystemdAvailable();
}

void Install(Status &status) {
  int ret = mkdir("/opt/gatekeeper", 0755);
  if (ret == -1) {
    if (errno == EEXIST) {
      // Already exists
    } else {
      AppendErrorMessage(status) += "Failed to create /opt/gatekeeper/";
      return;
    }
  }
  fs::Copy(fs::real, "/proc/self/exe", fs::real, "/opt/gatekeeper/gatekeeper",
           status, 0755);
  if (!status.Ok()) {
    AppendErrorMessage(status) += "Failed to copy main binary";
    return;
  }

  for (int i = 0; kKnownEnvironmentVariables[i]; ++i) {
    auto env = kKnownEnvironmentVariables[i];
    if (auto val = getenv(env)) {
      systemd::OverrideEnvironment("gatekeeper", env, val, status);
      if (!status.Ok()) {
        AppendErrorMessage(status) += "Failed to configure systemd service";
        return;
      }
    }
  }

  // Always set the LAN variable - just in case we can't find the interface
  // later.
  systemd::OverrideEnvironment("gatekeeper", "LAN", lan.name, status);
  if (!status.Ok()) {
    AppendErrorMessage(status) += "Failed to configure systemd service";
    return;
  }

  fs::Copy(fs::real_then_embedded, "gatekeeper.service", fs::real,
           "/opt/gatekeeper/gatekeeper.service", status, 0644);
  if (!status.Ok()) {
    AppendErrorMessage(status) += "Failed to copy systemd service file";
    return;
  }

  // Close all the ports so that new instance can bind them.
  webui::StopListening();
  dns::StopServer();
  dns::StopClient();
  dhcp::server.StopListening();
  // Also stop other epoll users - so that the current process can shut down.
  update::Stop();
  firewall::Stop();
  gatekeeper::UnhookSignals();

  ret = system("systemctl enable --now /opt/gatekeeper/gatekeeper.service");
  if (ret != 0) {
    AppendErrorMessage(status) +=
        "Installation finished but the service didn't start correctly. "
        "You might try checking what went wrong by lookuing into startup logs. "
        "This can be done with `journalctl -fu gatekeeper`. "
        "It's possible that Gatekeeper couldn't figure out which interface to "
        "run on. "
        "This can be fixed with `systemctl edit gatekeeper` to provide it "
        "with some startup parameters & then `systemctl restart gatekeeper` to "
        "restart it. "
        "See https://github.com/mafik/gatekeeper for full documentation.";

    // New instance failed to start so let's keep the current one operational.
    Status signals_status;
    gatekeeper::HookSignals(signals_status);

    update::Start();

    Status dhcp_status;
    dhcp::server.Listen(dhcp_status);

    Status dns_client_status;
    dns::StartClient(dns_client_status);

    Status dns_server_status;
    dns::StartServer(dns_server_status);

    Status firewall_status;
    firewall::Start(firewall_status);

    Status webui_status;
    webui::Start(webui_status);
  }
}

} // namespace gatekeeper::install