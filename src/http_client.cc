#include "http_client.hh"

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "ip.hh"
#include "status.hh"
#include "tcp.hh"
#include "tls.hh"
#include "unique_ptr.hh"

namespace maf::http {

// Note for future: this could be a really nice place to use coroutines.
static void ResponseReceived(RequestBase &get) {
  if (not OK(get.status)) {
    return;
  }
  while (get.inbox_pos < get.stream->inbox.size()) {
    StrView resp((char *)&get.stream->inbox[get.inbox_pos],
                 get.stream->inbox.size() - get.inbox_pos);
    if (get.parsing_state == RequestBase::ParsingState::Status) {
      size_t status_line_end = resp.find("\r\n");
      if (status_line_end == Str::npos) {
        return; // wait for more data
      }
      StrView status_line = resp.substr(0, status_line_end);
      StrView remaining = status_line;

      if (remaining.size() < 9) {
        AppendErrorMessage(get) += "HTTP response status line is too short \"" +
                                   Str(status_line) + "\"";
        return;
      }
      if (!remaining.starts_with("HTTP/1.1 ") and
          !remaining.starts_with("HTTP/1.0 ")) {
        AppendErrorMessage(get) += "Expected HTTP response to start with "
                                   "\"HTTP/1.1 \" or \"HTTP/1.0\" but "
                                   "instead got \"" +
                                   Str(status_line) + "\"";
        return;
      }
      remaining.remove_prefix(9);
      if (remaining.empty()) {
        AppendErrorMessage(get) +=
            "HTTP response status line is missing status code: \"" +
            Str(status_line) + "\"";
        return;
      }
      size_t status_code_end = remaining.find(' ');
      if (status_code_end == Str::npos) {
        AppendErrorMessage(get) +=
            "HTTP response status line is missing status code: \"" +
            Str(status_line) + "\"";
        return;
      }
      StrView status_code = remaining.substr(0, status_code_end);
      remaining.remove_prefix(status_code_end + 1);
      StrView reason_phrase = remaining;
      get.OnStatus(status_code, reason_phrase);
      get.parsing_state = RequestBase::ParsingState::Headers;
      get.inbox_pos += status_line_end + 2;
    } else if (get.parsing_state == RequestBase::ParsingState::Headers) {
      size_t header_end = resp.find("\r\n");
      if (header_end == Str::npos) {
        break; // wait for more data
      }
      if (header_end == 0) {
        get.parsing_state = RequestBase::ParsingState::Data;
        get.inbox_pos += 2;
        break;
      }
      StrView header = resp.substr(0, header_end);
      get.inbox_pos += header_end + 2;
      size_t colon = header.find(":");
      if (colon == Str::npos) {
        AppendErrorMessage(get) +=
            "Header is missing a colon: \"" + Str(header) + "\"";
        return;
      }
      StrView name = header.substr(0, colon);
      StrView value = header.substr(colon + 1);
      while (value.starts_with(' ')) {
        value = value.substr(1);
      }
      get.OnHeader(name, value);
    } else {
      get.OnData(resp);
      get.inbox_pos += resp.size();
    }
  }
}

static void SetUrl(RequestBase &request_base, Str url) {
  request_base.url = url;
  Size host_begin;
  if (url.starts_with("http://")) {
    host_begin = 7;
    request_base.protocol = Protocol::kHttp;
  } else if (url.starts_with("https://")) {
    host_begin = 8;
    request_base.protocol = Protocol::kHttps;
  } else {
    host_begin = 0;
    request_base.protocol = Protocol::kHttp;
  }

  Size host_end = url.find_first_of("/:", host_begin);
  request_base.port = request_base.protocol == Protocol::kHttp ? 80 : 443;
  if (host_end == Str::npos) {
    request_base.host = url.substr(host_begin);
    request_base.path = "/";
  } else {
    request_base.host = url.substr(host_begin, host_end - host_begin);
    if (url[host_end] == ':') {
      request_base.port = stoi(url.substr(host_end + 1));
    }
    size_t path_begin = url.find_first_of("/", host_end);
    if (path_begin == Str::npos) {
      request_base.path = "/";
    } else {
      request_base.path = url.substr(path_begin);
    }
  }
}

static void OpenStream(RequestBase &req) {
  if (req.protocol == Protocol::kHttp) {
    struct HttpStream : tcp::Connection {
      RequestBase &get;
      HttpStream(RequestBase &get, IP ip, U16 port) : get(get) {
        Connect({
            .remote_ip = ip,
            .remote_port = port,
        });
      }
      void NotifyReceived() override { ResponseReceived(get); }
      void NotifyClosed() override {
        if (this == get.stream.get()) {
          get.OnClosed();
        }
      }
    };
    req.stream = std::make_unique<HttpStream>(req, req.resolved_ip, req.port);
  } else if (req.protocol == Protocol::kHttps) {
    struct HttpsStream : tls::Connection {
      RequestBase &get;
      HttpsStream(RequestBase &get, IP ip, U16 port, Str host) : get(get) {
        Connect({tcp::Connection::Config{
                     .remote_ip = ip,
                     .remote_port = port,
                 },
                 host});
      }
      void NotifyReceived() override { ResponseReceived(get); }
      void NotifyClosed() override {
        if (this == get.stream.get()) {
          get.OnClosed();
        }
      }
    };
    req.stream =
        std::make_unique<HttpsStream>(req, req.resolved_ip, req.port, req.host);
  }

  auto Append = [&](StrView str) {
    req.stream->outbox.insert(req.stream->outbox.end(), str.begin(), str.end());
  };
  Append("GET ");
  Append(req.path);
  Append(" HTTP/1.1\r\n");
  Append("Host: ");
  Append(req.host);
  Append("\r\n");
  Append("Connection: close\r\n");
  Append("\r\n");
  req.stream->Send();
  req.inbox_pos = 0;
  req.parsing_state = RequestBase::ParsingState::Status;
}

RequestBase::RequestBase(Str url_arg) {
  SetUrl(*this, url_arg);
  dns_lookup.on_success = [this](IP ip) {
    this->resolved_ip = ip;
    OpenStream(*this);
  };
  dns_lookup.on_error = [this]() {
    AppendErrorMessage(*this) += "Couldn't resolve host \"" + host + "\"";
  };
  dns_lookup.Start(host);
}

RequestBase::~RequestBase() {}

void RequestBase::ClearInbox() {
  if (stream == nullptr) {
    return;
  }
  stream->inbox.erase(stream->inbox.begin(), stream->inbox.begin() + inbox_pos);
  inbox_pos = 0;
}

Get::Get(Str url, Callback callback) : RequestBase(url), callback(callback) {}

void Get::OnStatus(StrView status_code, StrView reason_phrase) {
  if (old_stream) {
    old_stream.reset();
  }
}

void Get::OnHeader(StrView name, StrView value) {
  if (name == "Location") {
    old_stream = std::move(stream);
    old_stream->Close();
    SetUrl(*this, Str(value));
    OpenStream(*this);
  }
}

void Get::OnData(StrView data) {
  if (data_begin == 0) {
    data_begin = inbox_pos;
  }
}

void Get::OnClosed() {
  response = StrView((char *)&stream->inbox[data_begin],
                     stream->inbox.size() - data_begin);
  callback();
};

} // namespace maf::http
