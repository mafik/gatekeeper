#pragma once

// Utilities for working with the DNS protocol.

#include <chrono>

#include "big_endian.hh"
#include "fn.hh"
#include "int.hh"
#include "optional.hh"
#include "str.hh"
#include "vec.hh"

namespace maf::dns {

// TTL used for outgoing DNS requests.
static constexpr std::chrono::steady_clock::duration kPendingTTL = 30s;
static constexpr std::chrono::steady_clock::duration kAuthoritativeTTL = 60s;

static constexpr uint16_t kServerPort = 53;

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

Str ToStr(Type);

enum class Class : uint16_t {
  IN = 1,
  ANY = 255,
};

Str ToStr(Class);

struct Question {
  Str domain_name = "";
  Type type = Type::A;
  Class class_ = Class::IN;
  Size LoadFrom(const char *ptr, Size len, Size offset);
  void write_to(Str &buffer) const;
  Str ToStr() const;
  Str to_html() const;
  auto operator<=>(const Question &other) const = default;
};

enum class ResponseCode {
  NO_ERROR = 0,
  FORMAT_ERROR = 1,
  SERVER_FAILURE = 2,
  NAME_ERROR = 3,
  NOT_IMPLEMENTED = 4,
  REFUSED = 5,
};

const char *ToStr(ResponseCode);

// Convert a domain name from "www.google.com" to "\3www\6google\3com\0".
Str EncodeDomainName(const Str &domain_name);

// Load a domain name from a DNS packet (supporting DNS compression).
//
// Returns a pair of domain name and the number of bytes read.
std::pair<Str, Size> LoadDomainName(const char *dns_message_base,
                                    Size dns_message_len, Size offset);

struct __attribute__((__packed__)) Header {
  enum class OperationCode {
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2,
    NOTIFY = 4,
    UPDATE = 5,
  };

  U16 id; // big endian

  // order swapped to match the order in the packet
  bool recursion_desired : 1;
  bool truncated : 1;
  bool authoritative : 1;
  OperationCode opcode : 4;
  bool reply : 1;

  ResponseCode response_code : 4;
  U8 reserved : 3;
  bool recursion_available : 1;

  Big<U16> question_count;
  Big<U16> answer_count;
  Big<U16> authority_count;
  Big<U16> additional_count;
  void write_to(Str &buffer);
  Str ToStr() const;
};

Str ToStr(Header::OperationCode code);

static_assert(sizeof(Header) == 12, "dns::Header is not packed correctly");

struct Record : public Question {
  Optional<std::chrono::steady_clock::time_point> expiration;
  U16 data_length;
  Str data;

  Size LoadFrom(const char *ptr, Size len, Size offset);
  void write_to(Str &buffer) const;
  U32 ttl() const;
  Str ToStr() const;
  Str pretty_value() const;
  Str to_html() const;
};

struct Message {
  Header header;
  Vec<Question> questions;
  Vec<Record> answers;
  Vec<Record> authority;
  Vec<Record> additional;

  void Parse(const char *ptr, Size len, Str &err);
  Str ToStr() const;
  void ForEachRecord(Fn<void(const Record &)> f) const;
};

} // namespace maf::dns