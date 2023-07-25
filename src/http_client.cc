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
void ResponseReceived(RequestBase &get) {
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

      if (remaining.size() < 8) {
        AppendErrorMessage(get) += "HTTP response status line is too short \"" +
                                   Str(status_line) + "\"";
        return;
      }
      if (!remaining.starts_with("HTTP/1.1 ")) {
        AppendErrorMessage(get) +=
            "Expected HTTP response to start with \"HTTP/1.1 \" but "
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

UniquePtr<Stream> MakeRequest(RequestBase &request_base, Str url) {
  enum {
    kHttp,
    kHttps,
  } scheme = kHttp;

  size_t host_begin;
  if (url.starts_with("http://")) {
    host_begin = 7;
    scheme = kHttp;
  } else if (url.starts_with("https://")) {
    host_begin = 8;
    scheme = kHttps;
  }

  size_t host_end = url.find_first_of("/:", host_begin);
  Str host;
  Str path;
  if (host_end == Str::npos) {
    host = url.substr(host_begin);
    path = "/";
  } else {
    host = url.substr(host_begin, host_end - host_begin);
    size_t path_begin = url.find_first_of("/", host_end);
    if (path_begin == Str::npos) {
      path = "/";
    } else {
      path = url.substr(path_begin);
    }
  }

  addrinfo hints = {
      .ai_family = AF_INET,
  };
  addrinfo *result;
  if (int ret = getaddrinfo(host.c_str(), nullptr, &hints, &result)) {
    AppendErrorMessage(request_base) +=
        "Couldn't get IP of host \"" + host + "\"";
    return nullptr;
  }

  IP ip(((sockaddr_in *)result->ai_addr)->sin_addr.s_addr);

  freeaddrinfo(result);

  UniquePtr<Stream> stream;
  if (scheme == kHttp) {
    struct HttpStream : tcp::Connection {
      RequestBase &get;
      HttpStream(RequestBase &get, IP ip) : get(get) {
        Connect({
            .remote_ip = ip,
            .remote_port = 80,
        });
      }
      void NotifyReceived() override { ResponseReceived(get); }
      void NotifyClosed() override {
        if (this == get.stream.get()) {
          get.OnClosed();
        }
      }
    };
    stream = std::make_unique<HttpStream>(request_base, ip);
  } else if (scheme == kHttps) {
    struct HttpsStream : tls::Connection {
      RequestBase &get;
      HttpsStream(RequestBase &get, IP ip, Str host) : get(get) {
        Connect({tcp::Connection::Config{
                     .remote_ip = ip,
                     .remote_port = 443,
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
    stream = std::make_unique<HttpsStream>(request_base, ip, host);
  }

  auto Append = [&](StrView str) {
    stream->outbox.insert(stream->outbox.end(), str.begin(), str.end());
  };
  Append("GET ");
  Append(path);
  Append(" HTTP/1.1\r\n");
  Append("Host: ");
  Append(host);
  Append("\r\n");
  Append("Connection: close\r\n");
  Append("\r\n");
  stream->Send();
  return stream;
}

RequestBase::RequestBase(Str url_arg)
    : url(url_arg), stream(MakeRequest(*this, url)) {}

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
  // LOG << "OnStatus: " << status_code << " " << reason_phrase;
  if (old_stream) {
    old_stream.reset();
  }
}

void Get::OnHeader(StrView name, StrView value) {
  // LOG << "OnHeader: " << name << ": " << value;
  if (name == "Location") {
    old_stream = std::move(stream);
    old_stream->Close();
    url = value;
    stream = MakeRequest(*this, url);
    inbox_pos = 0;
    parsing_state = ParsingState::Status;
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
