#pragma once

#include <source_location>
#include <string>
#include <vector>

struct Status {
  int errsv; // Saved errno value
  std::vector<std::source_location> locations;
  std::vector<std::string> messages;

  Status();

  std::string &operator()(const std::source_location location_arg =
                              std::source_location::current());

  bool Ok() const;
  std::string ToString() const;
};
