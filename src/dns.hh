#pragma once

#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "ip.hh"
#include "variant.hh"
#include "webui.hh"

namespace dns {

using std::string;
using std::variant;
using std::vector;
using std::chrono::steady_clock;

enum class Type : uint16_t {
  A = 1,
  NS = 2,
  CNAME = 5,
  SOA = 6,
  PTR = 12,
  MX = 15,
  TXT = 16,
  AAAA = 28,
  SRV = 33,
  HTTPS = 65,
  ANY = 255,
};

enum class Class : uint16_t {
  IN = 1,
  ANY = 255,
};

enum class ResponseCode {
  NO_ERROR = 0,
  FORMAT_ERROR = 1,
  SERVER_FAILURE = 2,
  NAME_ERROR = 3,
  NOT_IMPLEMENTED = 4,
  REFUSED = 5,
};

struct Question {
  string domain_name = "";
  Type type = Type::A;
  Class class_ = Class::IN;
  size_t LoadFrom(const uint8_t *ptr, size_t len, size_t offset);
  void write_to(string &buffer) const;
  string to_string() const;
  bool operator==(const Question &other) const;
  string to_html() const;
};

struct Record : public Question {
  variant<steady_clock::time_point, steady_clock::duration> expiration;
  uint16_t data_length;
  string data;

  size_t LoadFrom(const uint8_t *ptr, size_t len, size_t offset);
  void write_to(string &buffer) const;
  uint32_t ttl() const;
  string to_string() const;
  string pretty_value() const;
  string to_html() const;
};

struct __attribute__((__packed__)) Header {
  enum OperationCode {
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2,
    NOTIFY = 4,
    UPDATE = 5,
  };
  static string OperationCodeToString(OperationCode code);
  uint16_t id; // big endian

  // order swapped to match the order in the packet
  bool recursion_desired : 1;
  bool truncated : 1;
  bool authoritative : 1;
  OperationCode opcode : 4;
  bool reply : 1;

  ResponseCode response_code : 4;
  uint8_t reserved : 3;
  bool recursion_available : 1;

  uint16_t question_count;   // big endian
  uint16_t answer_count;     // big endian
  uint16_t authority_count;  // big endian
  uint16_t additional_count; // big endian
  void write_to(string &buffer);
  string to_string() const;
};

struct Message {
  Header header;
  Question question;
  vector<Record> answers;
  vector<Record> authority;
  vector<Record> additional;

  void Parse(const uint8_t *ptr, size_t len, string &err);
  string to_string() const;
  void ForEachRecord(std::function<void(const Record &)> f) const;
};

struct IncomingRequest {
  Header header;
  maf::IP client_ip;
  uint16_t client_port;
};

struct Entry {
  struct Ready {
    ResponseCode response_code;
    vector<Record> answers;
    vector<Record> authority;
    vector<Record> additional;
    string to_string() const;
    string to_html() const;
  };
  struct Pending {
    uint16_t outgoing_id;
    vector<IncomingRequest> incoming_requests;
  };

  Question question;
  mutable std::optional<steady_clock::time_point> expiration;
  mutable variant<Ready, Pending> state;

  void HandleIncomingRequest(const IncomingRequest &request) const;
  void HandleAnswer(const Message &msg, string &err) const;
  void UpdateExpiration(steady_clock::time_point new_expiration) const;
  bool operator==(const Question &other) const { return question == other; }
};

void Start(maf::Status &);
void Stop();

struct Table : webui::Table {
  struct Row {
    string question;
    Question orig_question;
    string expiration;
    steady_clock::time_point expiration_time;
  };
  vector<Row> rows;
  Table();
  void Update(RenderOptions &) override;
  int Size() const override;
  void Get(int row, int col, string &out) const override;
  string RowID(int row) const override;
};

extern Table table;

} // namespace dns