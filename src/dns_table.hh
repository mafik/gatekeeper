#pragma once

#include "optional.hh"
#include "webui.hh"

namespace maf::dns {

struct Table : webui::Table {
  struct Row {
    Str question;
    Str domain;
    U16 type;
    Str expiration;
    Optional<std::chrono::steady_clock::time_point> expiration_time;
  };
  std::vector<Row> rows;
  Table();
  void Update(RenderOptions &) override;
  int Size() const override;
  void Get(int row, int col, Str &out) const override;
  Str RowID(int row) const override;
};

extern Table table;

} // namespace maf::dns