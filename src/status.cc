#include "status.hh"

#include <cstring>

#include "format.hh"

Status::Status() : errsv(0), locations(), messages() {}

std::string &Status::operator()(const std::source_location location_arg) {
  if (errsv == 0) {
    errsv = errno;
  }
  locations.push_back(location_arg);
  messages.emplace_back();
  return messages.back();
}

bool Status::Ok() const { return errsv == 0 && messages.empty(); }

std::string Status::ToString() const {
  std::string ret;
  for (int i = messages.size() - 1; i >= 0; --i) {
    if (!ret.empty()) {
      ret += " ";
    }
    ret += messages[i];
    if (!ret.empty()) {
      ret += " ";
    }
    auto &location = locations[i];
    ret += f("(%s:%d).", location.file_name(), location.line());
  }
  if (!ret.empty()) {
    ret += " ";
  }
  if (errno) {
    ret += strerror(errsv);
  } else {
    ret += "Errno not set";
  }
  ret += ".";
  return ret;
}

void Status::Reset() {
  errsv = 0;
  locations.clear();
  messages.clear();
}
