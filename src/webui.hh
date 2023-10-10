#pragma once

#include <optional>
#include <string>
#include <vector>

#include "http.hh"

namespace webui {

struct Table {
  std::string id;
  std::string caption;
  std::vector<std::string> columns;
  Table(std::string id, std::string caption, std::vector<std::string> columns);

  struct RenderOptions {
    std::optional<int> sort_column = std::nullopt;
    bool sort_descending = false;
    int row_limit = 0;
    int row_offset = 0;
    static RenderOptions FromQuery(http::Request &);
  };

  // Called by the Web UI once, before the table is rendered. This allows tables
  // to pre-compute their data for greater rendering efficiency.
  virtual void Update(RenderOptions &);

  // Called during the rendering.
  virtual int Size() const = 0;

  // Called during the rendering.
  virtual void Get(int row, int col, std::string &out) const = 0;
  virtual std::string RowID(int row) const = 0;

  // Functions for rendering the table HTML.
  void RenderTABLE(std::string &html, RenderOptions &);
  void RenderTHEAD(std::string &html, RenderOptions &);
  void RenderTBODY(std::string &html, RenderOptions &);
  void RenderTR(std::string &html, int row);
  void RenderTFOOT(std::string &html, RenderOptions &);

  // Functions for rendering table to other formats.
  void RenderCSV(std::string &csv); // RFC 4180
  void RenderJSON(std::string &json);
};

void Start(maf::Status &);
void Stop();

// Similar to Stop - but doesn't terminate existing connections.
void StopListening();

// Nicely terminates all existing connections (sending any buffered data).
void FlushAndClose();

} // namespace webui
