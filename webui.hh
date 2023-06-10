#pragma once

#include <string>
#include <vector>

namespace webui {

struct Table {
  std::string id;
  std::string caption;
  std::vector<std::string> columns;
  Table(std::string id, std::string caption, std::vector<std::string> columns);
  void EmitTABLE(std::string &html);
  void EmitTHEAD(std::string &html);
  void EmitTBODY(std::string &html);
  void EmitTR(std::string &html, int row);
  virtual int Size() const = 0;
  virtual void Get(int row, int col, std::string &out) const = 0;
};

void Start(std::string &err);
void Stop();

} // namespace webui