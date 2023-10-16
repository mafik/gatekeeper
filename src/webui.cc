#include "webui.hh"

#include <chrono>
#include <deque>
#include <fcntl.h>
#include <map>
#include <optional>
#include <ranges>
#include <sys/stat.h>
#include <unistd.h>

#include "chrono.hh"
#include "config.hh"
#include "dhcp.hh"
#include "dns.hh"
#include "etc.hh"
#include "format.hh"
#include "http.hh"
#include "install.hh"
#include "ip.hh"
#include "log.hh"
#include "mac.hh"
#include "optional.hh"
#include "str.hh"
#include "traffic_log.hh"
#include "virtual_fs.hh"

namespace webui {

using namespace maf;
using namespace std;
using namespace http;
using namespace gatekeeper;
using chrono::steady_clock;

static constexpr int kPort = 1337;
Server server;
deque<string> messages;

bool WriteStaticFile(Response &response, Request &request) {
  if (request.path.size() <= 1) {
    return false;
  }
  // no slashes allowed (except the mandatory first one)
  if (!request.path.starts_with("/")) {
    return false;
  }
  if (request.path.find('/', 1) != string::npos) {
    return false;
  }
  string path = "static";
  path += request.path;
  Status status;
  fs::Map(
      fs::real_then_embedded, path.c_str(),
      [&](string_view content) { response.Write(content); }, status);
  return status.Ok();
}

map<string, Table *> &Tables() {
  static map<string, Table *> tables;
  return tables;
}

Table::Table(string id, string caption, vector<string> columns)
    : id(id), caption(caption), columns(columns) {
  Tables()[id] = this;
}

std::pair<int, int> RowRange(Table &t, Table::RenderOptions &opts) {
  int begin = opts.row_offset;
  int end = t.Size();
  if (opts.row_limit) {
    end = std::min(end, opts.row_offset + opts.row_limit);
  }
  return {begin, end};
}

string TableBeginA(Table &t, Table::RenderOptions opts) {
  auto [begin, end] = RowRange(t, opts);
  string html;
  html += "<a href=/";
  html += t.id;
  html += ".html?offset=";
  html += to_string(opts.row_offset);
  html += "&limit=";
  html += to_string(opts.row_limit);
  if (opts.sort_column) {
    html += "&sort=";
    html += to_string(*opts.sort_column);
    if (opts.sort_descending) {
      html += "&desc";
    }
  }
  html += " class=arrow hx-boost=true hx-ext=morphdom-swap hx-push-url=false"
          " hx-swap=\"morphdom outerHTML transition:true\" hx-target=#";
  html += t.id;
  html += " hx-select=#";
  html += t.id;
  html += ">";
  return html;
}

void Table::RenderTHEAD(string &html, RenderOptions &opts) {
  html += "<thead style=view-transition-name:";
  html += id;
  html += "-thead><tr class=round-top>";
  for (int i = 0; i < columns.size(); ++i) {
    auto &col = columns[i];
    html += "<th>";
    html += col;
    RenderOptions asc = opts;
    asc.sort_column = i;
    asc.sort_descending = false;
    asc.row_offset = 0;
    html += TableBeginA(*this, asc);
    html += "▲";
    html += "</a>";
    RenderOptions desc = asc;
    desc.sort_descending = true;
    html += TableBeginA(*this, desc);
    html += "▼";
    html += "</a>";
    html += "</th>";
  }
  html += "</tr></thead>";
}

void Table::RenderTR(string &html, int row) {
  html += "<tr id=";
  html += RowID(row);
  html += " style=view-transition-name:";
  html += RowID(row);
  html += ">";
  for (int col = 0; col < columns.size(); ++col) {
    html += "<td>";
    string cell;
    Get(row, col, cell);
    html += cell;
    html += "</td>";
  }
  html += "</tr>";
}

void Table::RenderTBODY(string &html, RenderOptions &opts) {
  html += "<tbody>";
  auto [begin, end] = RowRange(*this, opts);
  for (int row = begin; row < end; ++row) {
    RenderTR(html, row);
  }
  html += "</tbody>";
}

void Table::RenderTFOOT(std::string &html, RenderOptions &opts) {
  int s = Size();
  auto [begin, end] = RowRange(*this, opts);
  int n = end - begin;
  html += "<tfoot><tr class=round-bottom>";
  html += "<td colspan=";
  html += to_string(columns.size());
  html += ">";
  if (n == 0) {
    html += "No rows";
  } else if (n == 1) {
    html += "Row ";
    html += to_string(begin + 1);
  } else {
    html += "Rows ";
    html += to_string(begin + 1);
    html += "-";
    html += to_string(end);
  }
  html += " of ";
  html += to_string(s);
  html += " ";
  if (begin > 0) {
    RenderOptions prev = opts;
    prev.row_offset = std::max(0, begin - opts.row_limit);
    html += TableBeginA(*this, prev);
    html += "◀";
    html += "</a> ";
  }
  if (end < s) {
    RenderOptions next = opts;
    next.row_offset = end;
    html += TableBeginA(*this, next);
    html += "▶";
    html += "</a> ";
  }
  html += "<a href=/";
  html += id;
  html += ".html hx-boost=true hx-target=main hx-select=main"
          " hx-swap=\"morphdom outerHTML transition:true\""
          " hx-ext=morphdom-swap>Full table</a> <a href=/";
  html += id;
  html += ".csv>CSV</a> <a href=/";
  html += id;
  html += ".json>JSON</a>";
  html += "</td></tr></tfoot>";
}

void Table::RenderTABLE(string &html, RenderOptions &opts) {
  html += "<table id=";
  html += id;
  html += " style=view-transition-name:";
  html += id;
  html += "><caption>";
  html += caption;
  html += "</caption>";
  RenderTHEAD(html, opts);
  RenderTBODY(html, opts);
  RenderTFOOT(html, opts);
  html += "</table>";
}

void Table::Update(RenderOptions &) {}

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

struct ClientAliases {
  MAC mac;
  Vec<Str> aliases;
  Optional<IP> ip;

  ClientAliases(MAC mac) : mac(mac) {
    if (auto *hosts = etc::GetHosts(mac); hosts != nullptr) {
      aliases.insert(aliases.end(), hosts->begin(), hosts->end());
    }
    if (auto entry_it = dhcp::server.entries_by_mac.find(mac);
        entry_it != dhcp::server.entries_by_mac.end()) {
      auto *entry = *entry_it;
      if (entry->hostname != "" && find(aliases.begin(), aliases.end(),
                                        entry->hostname) == aliases.end()) {
        aliases.push_back(entry->hostname);
      }
    }
    if (aliases.empty()) {
      if (ip.has_value()) {
        aliases.push_back(ip->to_string());
      } else {
        aliases.push_back(mac.to_string());
      }
    }
  }
  ClientAliases(StrView mac_str) {
    if (mac.TryParse(mac_str.data())) {
      *this = ClientAliases(mac);
    } else {
      aliases.emplace_back(mac_str);
    }
  }

  // Return a short text representation for the given MAC address.
  Str GetTEXT() const { return aliases[0]; }

  // Return a non-interactive HTML tag that represents the given MAC address.
  Str GetSPAN() const {
    Str span = "<span class=client title=\"MAC=";
    span += mac.to_string();
    if (ip.has_value()) {
      span += " IP=";
      span += ip->to_string();
    }
    span += "\">";
    span += GetTEXT();
    span += "</span>";
    return span;
  }
};

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
    optional<steady_clock::time_point> last_activity_time;
    string hostnames;
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
  void Update(RenderOptions &opts) override {
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
    for (auto *entry : dhcp::server.entries_by_ip) {
      Row &row = RowByIP(entry->ip);
      row.mac = entry->mac;
      row.dhcp_hostname = entry->hostname;
      row.last_activity = FormatDuration(
          entry->last_request.transform([&](auto x) { return x - now; }),
          "never");
      row.last_activity_time = entry->last_request;
    }
    // Fill in the `hostnames` field.
    for (auto &r : rows) {
      string &out = r.hostnames;
      for (auto &h : r.etc_hosts_aliases) {
        if (!out.empty()) {
          out += " ";
        }
        out += h;
      }
      if (!r.dhcp_hostname.empty()) {
        bool found = false;
        for (auto &h : r.etc_hosts_aliases) {
          if (h == r.dhcp_hostname) {
            found = true;
            break;
          }
        }
        if (!found) {
          if (!out.empty()) {
            out += " ";
          }
          out += r.dhcp_hostname;
        }
      }
    }
    if (opts.sort_column) {
      sort(rows.begin(), rows.end(), [&](const Row &a, const Row &b) {
        bool result = true;
        if (opts.sort_column == 0) {
          result = a.ip.addr < b.ip.addr;
        } else if (opts.sort_column == 1) {
          result = a.mac < b.mac;
        } else if (opts.sort_column == 2) {
          result = a.hostnames < b.hostnames;
        } else if (opts.sort_column == 3) {
          result = a.last_activity_time < b.last_activity_time;
        }
        return opts.sort_descending ? !result : result;
      });
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
      out = r.hostnames;
      break;
    case 3:
      out = r.last_activity;
      break;
    }
  }
  std::string RowID(int row) const override {
    if (row < 0 || row >= rows.size()) {
      return "";
    }
    return f("devices-%08x", rows[row].ip.addr);
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
              {"Interface", "Domain name", "IP", "Network", "Hostname",
               "DNS servers"}) {}
  int Size() const override { return 1; }
  void Get(int row, int col, string &out) const override {
    switch (col) {
    case 0:
      out = lan.name;
      break;
    case 1:
      out = kLocalDomain;
      break;
    case 2:
      out = lan_ip.to_string();
      break;
    case 3:
      out = lan_network.LoggableString();
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

  std::string RowID(int row) const override { return "config-onlyrow"; }
};

ConfigTable config_table;

struct LogsTable : Table {
  LogsTable() : Table("logs", "Logs", {"Message"}) {}
  int Size() const override { return messages.size(); }
  void Get(int row, int col, string &out) const override {
    if (row < 0 || row >= messages.size()) {
      return;
    }
    out = messages[row];
  }
  std::string RowID(int row) const override {
    if (row < 0 || row >= messages.size()) {
      return "";
    }
    return f("log-%d", row);
  }
};

LogsTable logs_table;

struct TrafficGraph {
  struct RenderOptions {
    Optional<MAC> local_mac;
    Optional<IP> remote_ip;

    static RenderOptions FromQuery(Request &request) {
      RenderOptions opts{};
      if (request.query.contains("local")) {
        opts.local_mac = MAC();
        opts.local_mac->TryParse(request.query["local"].data());
      }
      if (request.query.contains("remote")) {
        opts.remote_ip = IP();
        opts.remote_ip->TryParse(request.query["remote"].data());
      }
      return opts;
    }

    using Entries = decltype(TrafficLog::entries);

    Entries Aggregate() const {
      Entries aggregated;
      // Performance note: we could exploit the fact that the traffic logs are
      // sorted to avoid linear scan here.
      QueryTraffic([&](const TrafficLog &log) {
        if (local_mac.has_value() && log.local_host != *local_mac) {
          return;
        }
        if (remote_ip.has_value() && log.remote_ip != *remote_ip) {
          return;
        }
        // Performance note: we could use iterators here for O(n) merge instead
        // of O(n*log(n)).
        for (auto &[time, bytes] : log.entries) {
          aggregated[time].up += bytes.up;
          aggregated[time].down += bytes.down;
        }
      });
      return aggregated;
    }

    auto operator<=>(const RenderOptions &) const = default;
  };

  static void RenderCANVAS(std::string &html, const RenderOptions &opts) {
    Str id = "traffic";
    vector<pair<Str, Str>> ws_params;
    if (opts.local_mac.has_value()) {
      ws_params.push_back(make_pair("local", opts.local_mac->to_string()));
      id += "-";
      id += opts.local_mac->to_string();
    }
    if (opts.remote_ip.has_value()) {
      ws_params.push_back(make_pair("remote", opts.remote_ip->to_string()));
      id += "-";
      id += opts.remote_ip->to_string();
    }
    Str params = "";
    bool first_param = true;
    for (auto &[k, v] : ws_params) {
      params += first_param ? '?' : '&';
      first_param = false;
      params += k;
      params += '=';
      params += v;
    }

    Str ws_url = "ws://";
    ws_url += lan_ip.to_string();
    ws_url += ":1337/traffic";
    ws_url += params;

    html += "<table id=";
    html += id;
    html += " style=view-transition-name:";
    html += id;
    html += "><caption>";
    if (opts.local_mac.has_value() && opts.remote_ip.has_value()) {
      html += "Traffic between ";
      html += ClientAliases(*opts.local_mac).GetSPAN();
      html += " and ";
      html += opts.remote_ip->to_string();
    } else if (opts.local_mac.has_value()) {
      html += "Traffic of ";
      html += ClientAliases(*opts.local_mac).GetSPAN();
    } else if (opts.remote_ip.has_value()) {
      html += "Traffic to ";
      html += opts.remote_ip->to_string();
    } else {
      html += "Traffic";
    }
    html += "</caption><tr class=round-top><td><canvas class=traffic width=600 "
            "height=348 data-ws=";
    html += ws_url;
    html += "></canvas></td></tr><tfoot><tr class=round-bottom><td>View as <a "
            "href=/traffic.html";
    html += params;
    html += " hx-boost=true hx-target=main hx-select=main hx-ext=morphdom-swap"
            " hx-swap=\"morphdom outerHTML transition:true\">HTML</a> <a "
            "href=/traffic.csv";
    html += params;
    html += ">CSV</a> <a href=/traffic.json";
    html += params;
    html += ">JSON</a>.";
    if (!opts.local_mac.has_value() || !opts.remote_ip.has_value()) {
      html += " Group by";
      if (!opts.local_mac.has_value()) {
        html += " <a href=/traffic.html";
        html += params.empty() ? "?" : params + "&";
        html += "local=all>LAN client</a>";
      }
      if (!opts.remote_ip.has_value()) {
        html += " <a href=/traffic.html";
        html += params.empty() ? "?" : params + "&";
        html += "remote=all>remote host</a>";
      }
      html += ".";
    }
    html += "</td></tr></tfoot></table>";
  }
};

Table::RenderOptions Table::RenderOptions::FromQuery(Request &request) {
  Table::RenderOptions opts;
  if (request.query.contains("sort")) {
    opts.sort_column = atoi(request.query["sort"].data());
  }
  opts.sort_descending = request.query.contains("desc");
  if (request.query.contains("limit")) {
    opts.row_limit = atoi(request.query["limit"].data());
  }
  if (request.query.contains("offset")) {
    opts.row_offset = atoi(request.query["offset"].data());
  }
  return opts;
}

static const void RenderHEADER(std::string &html) {
  html += "<header>";
  html += "<h1><a href=http://";
  html += lan_ip.to_string();
  html += ":";
  html += to_string(kPort);
  html += " hx-boost=true hx-target=main hx-select=main hx-ext=morphdom-swap"
          " hx-swap=\"morphdom outerHTML transition:true\">";
  html += "<img src=/gatekeeper.webp id=knight>Gatekeeper</a></h1>";
  html += "<div class=options><input type=checkbox id=autorefresh "
          "hx-get=/ hx-target=main hx-select=main "
          "hx-ext=morphdom-swap "
          "hx-swap=morphdom "
          "hx-preserve=true "
          "hx-trigger=\"every 1s [AutorefreshChecked()]\">"
          "<label for=autorefresh>Auto-refresh</label></div>";
  if (gatekeeper::install::CanInstall()) {
    html += "<div class=options><button hx-post=/install "
            "hx-target=body>Install</button></div>";
  }
  html += "<a class=github target=_blank "
          "href=https://github.com/mafik/gatekeeper><img src=/tentacles.webp "
          "alt=tentacles title=GitHub></a>";
  html += "</header>";
}

static const void RenderHeadTags(std::string &html) {
  html += "<meta charset=utf-8>";
  html += "<link rel=stylesheet href=/style.css>";
  html += "<link rel=icon type=image/x-icon href=/favicon.ico>";
  html += "<meta name=view-transition content=same-origin />";
  html += "<script src=/morphdom-umd-2.7.0.min.js></script>";
  html += "<script src=/htmx-1.9.2.min.js></script>";
  html += "<script src=/script.js></script>";
}

void RenderTableHTML(Response &response, Request &request, Table &t) {
  auto opts = Table::RenderOptions::FromQuery(request);
  t.Update(opts);
  string html;
  html += "<!doctype html>";
  html += "<html><head><title>";
  html += t.caption;
  html += " - Gatekeeper</title>";
  RenderHeadTags(html);
  html += "</head><body>";
  RenderHEADER(html);
  html += "<main>";
  t.RenderTABLE(html, opts);
  html += "</main></body></html>";
  response.Write(html);
}

void RenderTableCSV(Response &response, Request &request, Table &t) {
  auto opts = Table::RenderOptions::FromQuery(request);
  t.Update(opts);
  string csv;
  t.RenderCSV(csv);
  response.Write(csv);
}

void RenderTrafficCSV(Response &response, Request &request) {
  auto opts = TrafficGraph::RenderOptions::FromQuery(request);
  auto aggregated = opts.Aggregate();
  string csv = "Time,Bytes Sent,Bytes Downloaded\r\n";
  for (auto &[time, bytes] : aggregated) {
    csv += to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                         time.time_since_epoch())
                         .count());
    csv += ",";
    csv += to_string(bytes.up);
    csv += ",";
    csv += to_string(bytes.down);
    csv += "\r\n";
  }
  response.Write(csv);
}

void RenderTrafficJSON(Response &response, Request &request) {
  auto opts = TrafficGraph::RenderOptions::FromQuery(request);
  auto aggregated = opts.Aggregate();
  Str json = "[";
  for (auto &[time, bytes] : aggregated) {
    if (json.ends_with("]")) {
      json += ",\n";
    }
    json += "[";
    json += to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                          time.time_since_epoch())
                          .count());
    json += ",";
    json += to_string(bytes.up);
    json += ",";
    json += to_string(bytes.down);
    json += "]";
  }
  json += "]";
  response.Write(json);
}

void RenderTableJSON(Response &response, Request &request, Table &t) {
  auto opts = Table::RenderOptions::FromQuery(request);
  t.Update(opts);
  string json;
  t.RenderJSON(json);
  response.Write(json);
}

void RenderMainPage(Response &response, Request &request) {
  // When rendering the main page use fixed render options.
  Table::RenderOptions opts{
      .sort_column = nullopt,
      .row_limit = 5,
      .row_offset = 0,
  };
  for (auto [id, t] : Tables()) {
    t->Update(opts);
  }
  string html;
  html += "<!doctype html>";
  html += "<html><head>";
  html += "<title>Gatekeeper</title>";
  RenderHeadTags(html);
  html += "</head>";
  html += "<body>";
  RenderHEADER(html);
  html += "<main>";
  config_table.RenderTABLE(html, opts);
  devices_table.RenderTABLE(html, opts);
  Table::RenderOptions log_opts = opts;
  log_opts.row_offset = std::max<int>(0, messages.size() - opts.row_limit);
  logs_table.RenderTABLE(html, log_opts);
  TrafficGraph::RenderOptions traffic_opts;
  TrafficGraph::RenderCANVAS(html, traffic_opts);
  dhcp::table.RenderTABLE(html, opts);
  dns::table.RenderTABLE(html, opts);
  html += "</main></body></html>";
  response.Write(html);
}

void RenderTrafficHTML(Response &response, Request &request) {

  Str title = "Traffic";
  if (request.query.contains("local") && request.query.contains("remote")) {
    if (request.query["local"] == "all" && request.query["remote"] == "all") {
      title = "Traffic between every LAN client & remote host";
    } else if (request.query["local"] == "all") {
      title = "Traffic between every LAN client & ";
      title += request.query["remote"];
    } else if (request.query["remote"] == "all") {
      title = "Traffic between ";
      title += ClientAliases(request.query["local"].data()).GetTEXT();
      title += " & every remote host";
    } else {
      title = "Traffic between ";
      title += ClientAliases(request.query["local"].data()).GetTEXT();
      title += " & ";
      title += request.query["remote"];
    }
  } else if (request.query.contains("local")) {
    if (request.query["local"] == "all") {
      title = "Traffic by LAN client";
    } else {
      title = "Traffic of ";
      title += ClientAliases(request.query["local"].data()).GetTEXT();
    }
  } else if (request.query.contains("remote")) {
    if (request.query["remote"] == "all") {
      title = "Traffic to remote hosts";
    } else {
      title = "Traffic to ";
      title += request.query["remote"];
    }
  } else {
    title = "Traffic Summary";
  }

  string html;
  html += "<!doctype html>";
  html += "<html><head><title>";
  html += title;
  html += " - Gatekeeper</title>";
  RenderHeadTags(html);
  html += "</head><body>";
  RenderHEADER(html);
  html += "<main>";

  auto opts = TrafficGraph::RenderOptions::FromQuery(request);

  auto local_it = request.query.find("local");
  bool all_locals = false;
  if (local_it == request.query.end()) {
    // Aggregate all local hosts
    opts.local_mac = nullopt;
  } else if (local_it->second == "all") {
    all_locals = true;
  } else {
    // Select traffic for specific local host
    opts.local_mac = MAC();
    opts.local_mac->TryParse(local_it->second.data());
  }

  auto remote_it = request.query.find("remote");
  bool all_remotes = false;
  if (remote_it == request.query.end()) {
    // Aggregate all remote hosts
    opts.remote_ip = nullopt;
  } else if (remote_it->second == "all") {
    all_remotes = true;
  } else {
    // Select traffic for specific remote host
    opts.remote_ip = IP();
    opts.remote_ip->TryParse(remote_it->second.data());
  }

  if (all_locals && all_remotes) {
    // Draw separate graphs for each local & remote host.
    // This is a lot!
    gatekeeper::QueryTraffic([&](const TrafficLog &traffic_log) {
      opts.local_mac = traffic_log.local_host;
      opts.remote_ip = traffic_log.remote_ip;
      TrafficGraph::RenderCANVAS(html, opts);
    });
  } else if (all_locals) {
    // Draw separate graphs for each local host
    set<MAC> local_hosts;
    gatekeeper::QueryTraffic([&](const TrafficLog &traffic_log) {
      if (opts.remote_ip.has_value() &&
          opts.remote_ip != traffic_log.remote_ip) {
        return;
      }
      local_hosts.insert(traffic_log.local_host);
    });
    for (auto &local_host : local_hosts) {
      opts.local_mac = local_host;
      TrafficGraph::RenderCANVAS(html, opts);
    }
  } else if (all_remotes) {
    // Draw separate graphs for each remote host
    set<IP> remote_hosts;
    gatekeeper::QueryTraffic([&](const TrafficLog &traffic_log) {
      if (opts.local_mac.has_value() &&
          opts.local_mac != traffic_log.local_host) {
        return;
      }
      remote_hosts.insert(traffic_log.remote_ip);
    });
    for (auto &remote_host : remote_hosts) {
      opts.remote_ip = remote_host;
      TrafficGraph::RenderCANVAS(html, opts);
    }
  } else {
    TrafficGraph::RenderCANVAS(html, opts);
  }

  html += "</main></body></html>";
  response.Write(html);
}

multimap<TrafficGraph::RenderOptions, Connection *> traffic_websockets;

void RecordTraffic(chrono::system_clock::time_point time, MAC local_host,
                   IP remote_ip, U32 up, U32 down) {
  auto NotifyWebsockets = [&](auto iters) {
    auto [begin, end] = iters;
    for (auto it = begin; it != end; ++it) {
      auto &c = *it->second;
      string msg = "[";
      msg += to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                           time.time_since_epoch())
                           .count());
      msg += ",";
      msg += to_string(up);
      msg += ",";
      msg += to_string(down);
      msg += "]";
      c.SendText(msg);
    }
  };
  NotifyWebsockets(traffic_websockets.equal_range({local_host, remote_ip}));
  NotifyWebsockets(traffic_websockets.equal_range({local_host, nullopt}));
  NotifyWebsockets(traffic_websockets.equal_range({nullopt, nullopt}));
}

void OnWebsocketOpen(Connection &c, Request &req) {
  if (req.path == "/traffic") {
    auto opts = TrafficGraph::RenderOptions::FromQuery(req);
    traffic_websockets.emplace(opts, &c);

    auto aggregated = opts.Aggregate();

    Str msg = "";
    // Send data points in reverse so that the most recent points can be drawn
    // quicker.
    for (auto &[time, bytes] : aggregated | views::reverse) {
      msg.clear();
      msg += "[";
      msg += to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                           time.time_since_epoch())
                           .count());
      msg += ",";
      msg += to_string(bytes.up);
      msg += ",";
      msg += to_string(bytes.down);
      msg += "]";
      c.SendText(msg, false);
    }
    c.Flush();
  } else {
    c.Close(1002, "No such websocket");
  }
}

void OnWebsocketClose(Connection &c) {
  for (auto it = traffic_websockets.begin(); it != traffic_websockets.end();
       ++it) {
    if (it->second == &c) {
      it = traffic_websockets.erase(it);
      return;
    }
  }
}

void Handler(Response &response, Request &request) {
  string path(request.path);
  if (WriteStaticFile(response, request)) {
    // If a static file with the given path exists - just serve it.
    return;
  } else if (path.starts_with("/") && path.ends_with(".html")) {
    // Detail page.
    string id(path.substr(1, path.size() - 6));
    if (id == "traffic") {
      RenderTrafficHTML(response, request);
    } else if (auto it = Tables().find(id); it != Tables().end()) {
      RenderTableHTML(response, request, *it->second);
    } else {
      response.WriteStatus("404 Not Found");
      response.Write("Page not found");
    }
  } else if (path.starts_with("/") && path.ends_with(".csv")) {
    string id(path.substr(1, path.size() - 5));
    if (id == "traffic") {
      RenderTrafficCSV(response, request);
    } else if (auto it = Tables().find(id); it != Tables().end()) {
      RenderTableCSV(response, request, *it->second);
    } else {
      response.WriteStatus("404 Not Found");
      response.Write("Page not found");
    }
  } else if (path.starts_with("/") && path.ends_with(".json")) {
    string id(path.substr(1, path.size() - 6));
    if (id == "traffic") {
      RenderTrafficJSON(response, request);
    } else if (auto it = Tables().find(id); it != Tables().end()) {
      RenderTableJSON(response, request, *it->second);
    } else {
      response.WriteStatus("404 Not Found");
      response.Write("Page not found");
    }
  } else if (gatekeeper::install::CanInstall() && path == "/install") {
    Status status;
    gatekeeper::install::Install(status);
    if (OK(status)) {
      response.Write(R"(<!doctype html>
Installation completed successfully.<br>
<br>
Gatekeeper can now be managed as a systemd service. Example commands:<br>
<br>
<pre>
  systemctl status gatekeeper    # to see the status of the service
  systemctl stop gatekeeper      # to stop the service
  systemctl start gatekeeper     # to start the service
  journalctl -fu gatekeeper      # to see logs
</pre>
You can now go back to the <a href="/">main page</a>.
)");
      FlushAndClose();
    } else {
      response.WriteStatus("500 Internal Server Error");
      Str msg = status.ToString();
      ReplaceAll(msg, "\n", "<br>\n");
      response.Write("<!doctype html>" + msg);
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

void Start(Status &status) {
  server.handler = Handler;
  server.on_open = OnWebsocketOpen;
  server.on_close = OnWebsocketClose;
  server.Listen(
      http::Server::Config{.ip = lan_ip, .port = kPort, .interface = lan.name},
      status);
  if (!OK(status)) {
    return;
  }
  SetupLogging();
}

void Stop() {
  StopListening();
  for (auto *c : server.connections) {
    c->CloseTCP();
    delete c;
  }
  server.connections.clear();
}

void StopListening() { server.StopListening(); }

void FlushAndClose() {
  for (auto *c : server.connections) {
    c->Close(0, "");
  }
}

} // namespace webui