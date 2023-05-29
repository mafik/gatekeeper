#include "webui.hh"

#include <fcntl.h>
#include <unistd.h>

#include <deque>
#include <unordered_set>

#include "chrono.hh"
#include "config.hh"
#include "dhcp.hh"
#include "dns.hh"
#include "etc.hh"
#include "format.hh"
#include "http.hh"
#include "log.hh"

namespace webui {

using namespace std;
using namespace http;
using chrono::steady_clock;

static constexpr int kPort = 1337;
Server server;
deque<string> messages;

void WriteFile(Response &response, const char *path) {
  int f = open(path, O_RDONLY);
  if (f == -1) {
    response.WriteStatus("500 Internal Server Error");
    response.Write("Failed to open style.css");
    return;
  }
  char buf[1024 * 64];
  int len = read(f, buf, sizeof(buf));
  close(f);
  if (len == -1) {
    response.WriteStatus("500 Internal Server Error");
    response.Write("Failed to read style.css");
    return;
  }
  response.Write(string_view(buf, len));
}

unordered_set<string> static_files = {
    "/style.css",
    "/gatekeeper.gif",
    "/favicon.ico",
};

void Handler(Response &response, Request &request) {
  string path(request.path);
  if (static_files.contains(path)) {
    WriteFile(response, path.substr(1).c_str());
    return;
  }
  steady_clock::time_point now = steady_clock::now();
  string html;
  html.reserve(1024 * 64);
  html += "<!doctype html>";
  html += "<html><head><title>Gatekeeper</title><link rel=\"stylesheet\" "
          "href=\"/style.css\"><link rel=\"icon\" type=\"image/x-icon\" "
          "href=\"/favicon.ico\"></head><body>";
  html += R"(<script>
if (localStorage.refresh) {
  window.refresh_timeout = setTimeout(() => location.reload(), 1000);
}
function ToggleAutoRefresh() {
  if (localStorage.refresh) {
    delete localStorage.refresh;
  } else {
    localStorage.refresh = true;
  }
  location.reload();
}
</script>)";
  html += "<h1><a target=\"_blank\" "
          "href=\"https://github.com/mafik/gatekeeper\"><img "
          "src=\"/gatekeeper.gif\" id=\"knight\"></a>Gatekeeper <button "
          "onclick=\"ToggleAutoRefresh()\">Toggle Auto-refresh</button></h1>";
  auto table = [&](const char *caption, initializer_list<const char *> headers,
                   function<void()> inner) {
    html += "<table id=\"";
    html += Slugify(caption);
    html += "-table\"><caption>";
    html += caption;
    html += "</caption>";
    if (headers.size()) {
      html += "<tr>";
      for (auto &h : headers) {
        html += "<th>";
        html += h;
        html += "</th>";
      }
      html += "</tr>";
    }
    inner();
    html += "</table>";
  };
  table("Config", {"Key", "Value"}, [&]() {
    auto row = [&](const char *key, const string &value) {
      html += "<tr><td>";
      html += key;
      html += "</td><td>";
      html += value;
      html += "</td></tr>";
    };
    row("interface", interface_name);
    row("domain_name", kLocalDomain);
    row("server_ip", server_ip.to_string());
    row("netmask", netmask.to_string());
    row("/etc/hostname", etc::hostname);
  });
  table("/etc/hosts", {"hostname", "IP"}, [&]() {
    for (auto &[ip, aliases] : etc::hosts) {
      for (auto &alias : aliases) {
        html += "<tr><td>";
        html += alias;
        html += "</td><td>";
        html += ip.to_string();
        html += "</td></tr>";
      }
    }
  });
  table("/etc/ethers", {"MAC", "IP"}, [&]() {
    for (auto &[mac, ip] : etc::ethers) {
      html += "<tr><td>";
      html += mac.to_string();
      html += "</td><td>";
      html += ip.to_string();
      html += "</td></tr>";
    }
  });
  table("/etc/resolv.conf", {"IP"}, [&]() {
    for (auto &ip : etc::resolv) {
      html += "<tr><td>";
      html += ip.to_string();
      html += "</td></tr>";
    }
  });
  table("DHCP",
        {"IP", "Client ID", "Hostname", "TTL", "Last activity", "Stable"},
        [&]() {
          for (auto &[ip, entry] : dhcp::server.entries) {
            html += "<tr><td>";
            html += ip.to_string();
            html += "</td><td>";
            html += entry.client_id;
            html += "</td><td>";
            html += entry.hostname;
            html += "</td><td>";
            html += FormatDuration(
                entry.expiration.transform([&](auto e) { return e - now; }));
            html += "</td><td>";
            html += FormatDuration(
                entry.last_request.transform([&](auto x) { return x - now; }),
                "never");
            html += "</td><td>";
            html += entry.stable ? "✓" : "";
            html += "</td></tr>";
          }
        });
  table("Log", {"Message"}, [&]() {
    for (auto &line : messages) {
      html += "<tr><td>";
      html += line;
      html += "</td></tr>";
    }
  });
  table("DNS cache", {"Question", "TTL", "State"}, [&]() {
    auto emit_dns_entry = [&](const dns::Entry &entry) {
      html += "<tr><td>";
      html += entry.question.to_html();
      html += "</td><td>";
      html += FormatDuration(
          entry.expiration.transform([&](auto e) { return e - now; }));
      html += "</td><td>";
      visit(
          overloaded{
              [&](const dns::Entry::Ready &ready) { html += ready.to_html(); },
              [&](const dns::Entry::Pending &pending) { html += "Pending"; }},
          entry.state);
      html += "</td></tr>";
    };

    dns::ForEachEntry([&](const dns::Entry &entry) { emit_dns_entry(entry); });
  });
  html += "</body></html>";
  response.Write(html);
}

const char *kANSIColorHex[256] = {
    "#000000", "#800000", "#008000", "#808000", "#000080", "#800080", "#008080",
    "#c0c0c0", "#808080", "#ff0000", "#00ff00", "#ffff00", "#0000ff", "#ff00ff",
    "#00ffff", "#ffffff", "#000000", "#00005f", "#000087", "#0000af", "#0000d7",
    "#0000ff", "#005f00", "#005f5f", "#005f87", "#005faf", "#005fd7", "#005fff",
    "#008700", "#00875f", "#008787", "#0087af", "#0087d7", "#0087ff", "#00af00",
    "#00af5f", "#00af87", "#00afaf", "#00afd7", "#00afff", "#00d700", "#00d75f",
    "#00d787", "#00d7af", "#00d7d7", "#00d7ff", "#00ff00", "#00ff5f", "#00ff87",
    "#00ffaf", "#00ffd7", "#00ffff", "#5f0000", "#5f005f", "#5f0087", "#5f00af",
    "#5f00d7", "#5f00ff", "#5f5f00", "#5f5f5f", "#5f5f87", "#5f5faf", "#5f5fd7",
    "#5f5fff", "#5f8700", "#5f875f", "#5f8787", "#5f87af", "#5f87d7", "#5f87ff",
    "#5faf00", "#5faf5f", "#5faf87", "#5fafaf", "#5fafd7", "#5fafff", "#5fd700",
    "#5fd75f", "#5fd787", "#5fd7af", "#5fd7d7", "#5fd7ff", "#5fff00", "#5fff5f",
    "#5fff87", "#5fffaf", "#5fffd7", "#5fffff", "#870000", "#87005f", "#870087",
    "#8700af", "#8700d7", "#8700ff", "#875f00", "#875f5f", "#875f87", "#875faf",
    "#875fd7", "#875fff", "#878700", "#87875f", "#878787", "#8787af", "#8787d7",
    "#8787ff", "#87af00", "#87af5f", "#87af87", "#87afaf", "#87afd7", "#87afff",
    "#87d700", "#87d75f", "#87d787", "#87d7af", "#87d7d7", "#87d7ff", "#87ff00",
    "#87ff5f", "#87ff87", "#87ffaf", "#87ffd7", "#87ffff", "#af0000", "#af005f",
    "#af0087", "#af00af", "#af00d7", "#af00ff", "#af5f00", "#af5f5f", "#af5f87",
    "#af5faf", "#af5fd7", "#af5fff", "#af8700", "#af875f", "#af8787", "#af87af",
    "#af87d7", "#af87ff", "#afaf00", "#afaf5f", "#afaf87", "#afafaf", "#afafd7",
    "#afafff", "#afd700", "#afd75f", "#afd787", "#afd7af", "#afd7d7", "#afd7ff",
    "#afff00", "#afff5f", "#afff87", "#afffaf", "#afffd7", "#afffff", "#d70000",
    "#d7005f", "#d70087", "#d700af", "#d700d7", "#d700ff", "#d75f00", "#d75f5f",
    "#d75f87", "#d75faf", "#d75fd7", "#d75fff", "#d78700", "#d7875f", "#d78787",
    "#d787af", "#d787d7", "#d787ff", "#d7af00", "#d7af5f", "#d7af87", "#d7afaf",
    "#d7afd7", "#d7afff", "#d7d700", "#d7d75f", "#d7d787", "#d7d7af", "#d7d7d7",
    "#d7d7ff", "#d7ff00", "#d7ff5f", "#d7ff87", "#d7ffaf", "#d7ffd7", "#d7ffff",
    "#ff0000", "#ff005f", "#ff0087", "#ff00af", "#ff00d7", "#ff00ff", "#ff5f00",
    "#ff5f5f", "#ff5f87", "#ff5faf", "#ff5fd7", "#ff5fff", "#ff8700", "#ff875f",
    "#ff8787", "#ff87af", "#ff87d7", "#ff87ff", "#ffaf00", "#ffaf5f", "#ffaf87",
    "#ffafaf", "#ffafd7", "#ffafff", "#ffd700", "#ffd75f", "#ffd787", "#ffd7af",
    "#ffd7d7", "#ffd7ff", "#ffff00", "#ffff5f", "#ffff87", "#ffffaf", "#ffffd7",
    "#ffffff", "#080808", "#121212", "#1c1c1c", "#262626", "#303030", "#3a3a3a",
    "#444444", "#4e4e4e", "#585858", "#626262", "#6c6c6c", "#767676", "#808080",
    "#8a8a8a", "#949494", "#9e9e9e", "#a8a8a8", "#b2b2b2", "#bcbcbc", "#c6c6c6",
    "#d0d0d0", "#dadada", "#e4e4e4", "#eeeeee"};

string ANSIToHTML(string_view buf) {
  string r;
  for (int i = 0; i < buf.size(); ++i) {
    char c = buf[i];
    if (c == '\n') {
      r += "<br>";
    } else if (c == '\033') {
      if (buf.substr(i).starts_with("\033[38;5;")) { // 256-color foreground
        int start = i + 7;
        int end = buf.find('m', start);
        if (end == string_view::npos) {
          r += "�";
          continue;
        }
        int color = atoi(buf.substr(start, end - start).data());
        if (color < 0 || color >= 256) {
          r += "�";
          continue;
        }
        r += "<span style=\"color: ";
        r += kANSIColorHex[color];
        r += "\">";
        i = end;
      } else if (buf.substr(i).starts_with("\033[39m")) { // reset foreground
        r += "</span>";
        i += 4;
      } else {
        r += "�";
      }
    } else {
      r += c;
    }
  }
  return r;
}

void SetupLogInterception() {
  auto default_logger = std::move(loggers.front());
  loggers.clear();
  loggers.push_back([l = std::move(default_logger)](const LogEntry &e) {
    messages.emplace_back(ANSIToHTML(e.buffer));
    while (messages.size() > 20) {
      messages.pop_front();
    }
    if (e.log_level >= LogLevel::Error) {
      l(e);
    }
  });
}

void Start(string &err) {
  server.handler = Handler;
  server.Listen(http::Server::Config{.ip = server_ip,
                                     .port = kPort,
                                     .interface = interface_name},
                err);
  if (!err.empty()) {
    return;
  }
  SetupLogInterception();
}

} // namespace webui