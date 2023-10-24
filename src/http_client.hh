#pragma once

#include <functional>

#include "dns_client.hh"
#include "status.hh"
#include "str.hh"
#include "stream.hh"
#include "unique_ptr.hh"

namespace maf::http {

enum class Protocol : U8 {
  kHttp,
  kHttps,
};

// Base class for HTTP requests.
//
// Accumulates the HTTP response in the `inbox` buffer.
struct RequestBase {
  Str url;
  Protocol protocol;
  Str host;
  U16 port;
  Str path;
  IP resolved_ip;
  dns::LookupIPv4 dns_lookup;
  UniquePtr<Stream> stream;

  enum class ParsingState {
    Status,
    Headers,
    Data,
  } parsing_state = ParsingState::Status;
  Size inbox_pos = 0;

  RequestBase(Str url);
  virtual ~RequestBase();

  // RequestBase accumulates the HTTP response in the `inbox` buffer. This
  // may become problematic for large responses. This method will clear the
  // `inbox` buffer (invalidating any `StrView` pointing at it).
  void ClearInbox();

  virtual void OnStatus(StrView status_code, StrView reason_phrase) {}
  virtual void OnHeader(StrView name, StrView value) {}
  virtual void OnData(StrView data) {}
  virtual void OnClosed() {}

  Status status; // this is only used when there is no `stream`
  operator Status &() { return status; }
};

struct Get : RequestBase {
  using Callback = std::function<void()>;
  StrView response;
  Size data_begin = 0;
  Callback callback;

  UniquePtr<Stream> old_stream;

  Get(Str url, Callback callback);

  void OnStatus(StrView status_code, StrView reason_phrase) override;
  void OnHeader(StrView name, StrView value) override;
  void OnData(StrView data) override;
  void OnClosed() override;
};

} // namespace maf::http