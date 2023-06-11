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

map<string, Table *> &Tables() {
  static map<string, Table *> tables;
  return tables;
}

Table::Table(string id, string caption, vector<string> columns)
    : id(id), caption(caption), columns(columns) {
  Tables()[id] = this;
}

void Table::RenderTHEAD(string &html) {
  html += "<thead><tr class=round-top>";
  for (auto &h : columns) {
    html += "<th>";
    html += h;
    html += "</th>";
  }
  html += "</tr></thead>";
}

void Table::RenderTR(string &html, int row) {
  html += "<tr>";
  for (int col = 0; col < columns.size(); ++col) {
    html += "<td>";
    string cell;
    Get(row, col, cell);
    html += cell;
    html += "</td>";
  }
  html += "</tr>";
}

void Table::RenderTBODY(string &html) {
  html += "<tbody>";
  for (int row = 0; row < Size(); ++row) {
    RenderTR(html, row);
  }
  html += "</tbody>";
}

void Table::RenderTFOOT(std::string &html) {
  html += "<tfoot><tr class=round-bottom>";
  html += "<td colspan=\"";
  html += to_string(columns.size());
  html += "\">";
  html += to_string(Size());
  html += " rows";
  html += " <a href=\"/";
  html += id;
  html += ".html\">Full table</a> <a href=\"/";
  html += id;
  html += ".csv\">CSV</a> <a href=\"/";
  html += id;
  html += ".json\">JSON</a>";
  html += "</td></tr></tfoot>";
}

void Table::RenderTABLE(string &html) {
  html += "<table id=\"";
  html += id;
  html += "\"><caption>";
  html += caption;
  html += "</caption>";
  RenderTHEAD(html);
  RenderTBODY(html);
  RenderTFOOT(html);
  html += "</table>";
}

void Table::Update() {}

static void AppendCSVString(string &csv, string_view s) {
  bool needs_escaping = s.contains(',') || s.contains('"') || s.contains('\n');
  if (needs_escaping) {
    csv += '"';
    for (auto c : s) {
      if (c == '"') {
        csv += "\"\"";
      } else {
        csv += c;
      }
    }
    csv += '"';
  } else {
    csv += s;
  }
}

void Table::RenderCSV(std::string &csv) {
  for (int col = 0; col < columns.size(); ++col) {
    if (col > 0) {
      csv += ",";
    }
    AppendCSVString(csv, columns[col]);
  }
  csv += "\r\n";
  for (int row = 0; row < Size(); ++row) {
    for (int col = 0; col < columns.size(); ++col) {
      if (col > 0) {
        csv += ",";
      }
      string cell;
      Get(row, col, cell);
      AppendCSVString(csv, cell);
    }
    csv += "\r\n";
  }
}

void EscapeJSONString(string &out, string_view s) {
  for (auto c : s) {
    switch (c) {
    case '\b':
      out += "\\b";
      break;
    case '\f':
      out += "\\f";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    case '"':
      out += "\\\"";
      break;
    case '\\':
      out += "\\\\";
      break;
    default:
      out += c;
      break;
    }
  }
}

void Table::RenderJSON(std::string &json) {
  json += "[";
  for (int row = 0; row < Size(); ++row) {
    if (row > 0) {
      json += ",";
    }
    json += "{";
    for (int col = 0; col < columns.size(); ++col) {
      if (col > 0) {
        json += ",";
      }
      json += "\"";
      EscapeJSONString(json, columns[col]);
      json += "\":\"";
      string cell;
      Get(row, col, cell);
      EscapeJSONString(json, cell);
      json += "\"";
    }
    json += "}";
  }
  json += "]";
}

struct DevicesTable : Table {
  DevicesTable()
      : Table("devices", "Devices",
              {"IP", "MAC", "Hostnames", "Last activity"}) {}
  struct Row {
    IP ip;
    optional<MAC> mac;
    vector<string> etc_hosts_aliases;
    string dhcp_hostname;
    string last_activity;
  };
  vector<Row> rows;

  Row &RowByIP(IP ip) {
    for (auto &r : rows) {
      if (r.ip == ip) {
        return r;
      }
    }
    rows.emplace_back();
    rows.back().ip = ip;
    return rows.back();
  }
  void Update() override {
    rows.clear();
    steady_clock::time_point now = steady_clock::now();
    for (auto &[ip, aliases] : etc::hosts) {
      Row &row = RowByIP(ip);
      for (auto &alias : aliases) {
        row.etc_hosts_aliases.push_back(alias);
      }
    }
    for (auto &[mac, ip] : etc::ethers) {
      Row &row = RowByIP(ip);
      row.mac = mac;
    }
    for (auto &[ip, entry] : dhcp::server.entries) {
      Row &row = RowByIP(ip);
      if (MAC mac; mac.TryParse(entry.client_id.c_str())) {
        row.mac = mac;
      }
      row.dhcp_hostname = entry.hostname;
      row.last_activity = FormatDuration(
          entry.last_request.transform([&](auto x) { return x - now; }),
          "never");
    }
  }

  int Size() const override { return rows.size(); }
  void Get(int row, int col, string &out) const override {
    if (row < 0 || row >= rows.size()) {
      return;
    }
    const Row &r = rows[row];
    switch (col) {
    case 0:
      out = r.ip.to_string();
      break;
    case 1:
      if (r.mac) {
        out = r.mac->to_string();
      }
      break;
    case 2:
      for (auto &h : r.etc_hosts_aliases) {
        if (!out.empty()) {
          out += " ";
        }
        out += h;
      }
      if (!r.dhcp_hostname.empty()) {
        if (!out.empty()) {
          out += " ";
        }
        out += r.dhcp_hostname;
      }
      break;
    case 3:
      out = r.last_activity;
      break;
    }
  }
};

// TODO: status indicator (never/away/active)
// TODO: DHCP / DNS activity
// TODO: link to device details page
// TODO: pagination
DevicesTable devices_table;

struct ConfigTable : Table {
  ConfigTable()
      : Table("config", "Config",
              {"Interface", "Domain name", "IP", "Network mask", "Hostname",
               "DNS servers"}) {}
  int Size() const override { return 1; }
  void Get(int row, int col, string &out) const override {
    switch (col) {
    case 0:
      out = interface_name;
      break;
    case 1:
      out = kLocalDomain;
      break;
    case 2:
      out = server_ip.to_string();
      break;
    case 3:
      out = netmask.to_string();
      break;
    case 4:
      out = etc::hostname;
      break;
    case 5:
      for (auto &ip : etc::resolv) {
        if (!out.empty()) {
          out += " ";
        }
        out += ip.to_string();
      }
      break;
    }
  }
};

ConfigTable config_table;

struct LogTable : Table {
  LogTable() : Table("log", "Log", {"Message"}) {}
  int Size() const override { return messages.size(); }
  void Get(int row, int col, string &out) const override {
    if (row < 0 || row >= messages.size()) {
      return;
    }
    out = messages[row];
  }
};

LogTable log_table;

void RenderTableHTML(Response &response, Request &request, Table &t) {
  t.Update();
  string html;
  html += "<!doctype html>";
  html += "<html><head><title>";
  html += t.caption;
  html += " - Gatekeeper</title><link rel=\"stylesheet\" "
          "href=\"/style.css\"><link rel=\"icon\" type=\"image/x-icon\" "
          "href=\"/favicon.ico\"></head><body>";
  t.RenderTABLE(html);
  html += "</body></html>";
  response.Write(html);
}

void RenderTableCSV(Response &response, Request &request, Table &t) {
  t.Update();
  string csv;
  t.RenderCSV(csv);
  response.Write(csv);
}

void RenderTableJSON(Response &response, Request &request, Table &t) {
  t.Update();
  string json;
  t.RenderJSON(json);
  response.Write(json);
}

void RenderMainPage(Response &response, Request &request) {
  for (auto [id, t] : Tables()) {
    t->Update();
  }
  string html;
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
  config_table.RenderTABLE(html);
  devices_table.RenderTABLE(html);
  log_table.RenderTABLE(html);
  dhcp::table.RenderTABLE(html);
  dns::table.RenderTABLE(html);
  html += "</body></html>";
  response.Write(html);
}

void Handler(Response &response, Request &request) {
  string path(request.path);
  if (static_files.contains(path)) {
    WriteFile(response, path.substr(1).c_str());
    return;
  } else if (path.starts_with("/") && path.ends_with(".html")) {
    string id(path.substr(1, path.size() - 6));
    if (auto it = Tables().find(id); it != Tables().end()) {
      RenderTableHTML(response, request, *it->second);
    } else {
      response.WriteStatus("404 Not Found");
      response.Write("Table not found");
    }
  } else if (path.starts_with("/") && path.ends_with(".csv")) {
    string id(path.substr(1, path.size() - 5));
    if (auto it = Tables().find(id); it != Tables().end()) {
      RenderTableCSV(response, request, *it->second);
    } else {
      response.WriteStatus("404 Not Found");
      response.Write("Table not found");
    }
  } else if (path.starts_with("/") && path.ends_with(".json")) {
    string id(path.substr(1, path.size() - 6));
    if (auto it = Tables().find(id); it != Tables().end()) {
      RenderTableJSON(response, request, *it->second);
    } else {
      response.WriteStatus("404 Not Found");
      response.Write("Table not found");
    }
  } else {
    RenderMainPage(response, request);
  }
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

void SetupLogging() {
  loggers.push_back([](const LogEntry &e) {
    messages.emplace_back(ANSIToHTML(e.buffer));
    while (messages.size() > 20) {
      messages.pop_front();
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
  SetupLogging();
}

void Stop() {
  server.StopListening();
  for (auto *c : server.connections) {
    c->CloseTCP();
    delete c;
  }
  server.connections.clear();
}

} // namespace webui