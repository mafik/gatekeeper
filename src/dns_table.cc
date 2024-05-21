#include "dns_table.hh"
#include "chrono.hh"
#include "dns_client.hh"

using namespace std;

namespace maf::dns {

Table::Table() : webui::Table("dns", "DNS", {"Expiration", "Entry"}) {}

void Table::Update(RenderOptions &opts) {
  rows.clear();
  auto now = chrono::steady_clock::now();
  for (auto *entry : Entry::cache) {

    Optional<chrono::steady_clock::duration> expiration =
        entry->expiration.transform(
            [&](auto expiration) { return expiration - now; });
    rows.emplace_back(Row{
        .question = entry->question.to_html(),
        .domain = entry->question.domain_name,
        .type = (U16)entry->question.type,
        .expiration = FormatDuration(expiration),
        .expiration_time = entry->expiration,
    });
  }
  if (opts.sort_column) {
    sort(rows.begin(), rows.end(), [&](const Row &a, const Row &b) {
      bool result = true;
      if (opts.sort_column == 0) {
        if (a.expiration_time.has_value() && b.expiration_time.has_value()) {
          result = *a.expiration_time < *b.expiration_time;
        } else if (a.expiration_time.has_value()) {
          result = true;
        } else if (b.expiration_time.has_value()) {
          result = false;
        } else {
          result = a.domain < b.domain;
        }
      } else if (opts.sort_column == 1) {
        result = a.question < b.question;
      }
      return opts.sort_descending ? !result : result;
    });
  }
}

int Table::Size() const { return rows.size(); }

void Table::Get(int row, int col, string &out) const {
  if (row < 0 || row >= Size()) {
    return;
  }
  switch (col) {
  case 0:
    out = rows[row].expiration;
    break;
  case 1:
    out = rows[row].question;
    break;
  }
}

std::string Table::RowID(int row) const {
  if (row < 0 || row >= rows.size()) {
    return "";
  }
  string id = "dns-";
  for (char c : rows[row].domain) {
    if (isalnum(c)) {
      id += c;
    } else {
      id += '-';
    }
  }
  id += '-';
  id += ToStr((Type)rows[row].type);
  return id;
}

Table table;

} // namespace maf::dns