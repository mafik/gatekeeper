#include "status.hh"

#include <cstring>

#include "format.hh"

namespace maf {

Status::Status() : errsv(0) {}

Str &Status::operator()(const std::source_location location_arg) {
  if (errsv == 0) {
    errsv = errno;
    errno = 0;
  }
  entry.reset(new Entry{
      .next = std::move(entry), .location = location_arg, .message = {}});
  return entry->message;
}

bool Status::Ok() const { return errsv == 0 && entry == nullptr; }

Str Status::ToString() const {
  Str ret;
  for (Entry *i = entry.get(); i != nullptr; i = i->next.get()) {
    if (!ret.empty()) {
      ret += " ";
    }
    ret += i->message;
    if (!ret.empty()) {
      ret += " ";
    }
    auto &location = i->location;
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
  entry.reset();
}

} // namespace maf