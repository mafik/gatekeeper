#pragma once

#include <string>
#include <vector>

namespace webui {

struct Table {
  std::string id;
  std::string caption;
  std::vector<std::string> columns;
  Table(std::string id, std::string caption, std::vector<std::string> columns);

  // Called by the Web UI once, before the table is rendered. This allows tables
  // to pre-compute their data for greater rendering efficiency.
  virtual void Update();

  // Called during the rendering.
  virtual int Size() const = 0;

  // Called during the rendering.
  virtual void Get(int row, int col, std::string &out) const = 0;

  // Functions for rendering the table HTML.
  void RenderTABLE(std::string &html);
  void RenderTHEAD(std::string &html);
  void RenderTBODY(std::string &html);
  void RenderTR(std::string &html, int row);
  void RenderTFOOT(std::string &html);

  // Functions for rendering table to other formats.
  void RenderCSV(std::string &csv); // RFC 4180
  void RenderJSON(std::string &json);
};

void Start(std::string &err);
void Stop();

} // namespace webui