#include "dns_utils.hh"

#include <netinet/in.h>

#include "format.hh"
#include "hex.hh"

using namespace maf;

namespace maf::dns {

using namespace std;

Str ToStr(Type t) {
  switch (t) {
  case Type::A:
    return "A";
  case Type::NS:
    return "NS";
  case Type::CNAME:
    return "CNAME";
  case Type::SOA:
    return "SOA";
  case Type::PTR:
    return "PTR";
  case Type::MX:
    return "MX";
  case Type::TXT:
    return "TXT";
  case Type::AAAA:
    return "AAAA";
  case Type::SRV:
    return "SRV";
  case Type::HTTPS:
    return "HTTPS";
  case Type::ANY:
    return "ANY";
  default:
    return f("UNKNOWN(%hu)", t);
  }
}

Str ToStr(Class c) {
  switch (c) {
  case Class::IN:
    return "IN";
  case Class::ANY:
    return "ANY";
  default:
    return f("UNKNOWN(%hu)", c);
  }
}

const char *ToStr(ResponseCode code) {
  switch (code) {
  case ResponseCode::NO_ERROR:
    return "NO_ERROR";
  case ResponseCode::FORMAT_ERROR:
    return "FORMAT_ERROR";
  case ResponseCode::SERVER_FAILURE:
    return "SERVER_FAILURE";
  case ResponseCode::NAME_ERROR:
    return "NAME_ERROR";
  case ResponseCode::NOT_IMPLEMENTED:
    return "NOT_IMPLEMENTED";
  case ResponseCode::REFUSED:
    return "REFUSED";
  default:
    return "UNKNOWN";
  }
}

Str EncodeDomainName(const Str &domain_name) {
  Str buffer;
  Size seg_begin = 0;
encode_segment:
  Size seg_end = domain_name.find('.', seg_begin);
  if (seg_end == -1)
    seg_end = domain_name.size();
  Size n = seg_end - seg_begin;
  if (n) { // don't encode 0-length segments - because \0 marks the end of
           // domain name
    buffer.append({(char)n});
    buffer.append(domain_name, seg_begin, n);
  }
  if (seg_end < domain_name.size()) {
    seg_begin = seg_end + 1;
    goto encode_segment;
  }
  buffer.append({0});
  return buffer;
}

pair<Str, Size> LoadDomainName(const char *dns_message_base,
                               Size dns_message_len, Size offset) {
  Size start_offset = offset;
  Str domain_name;
  while (true) {
    if (offset >= dns_message_len) {
      return make_pair("", 0);
    }
    char n = dns_message_base[offset++];
    if (n == 0) {
      return make_pair(domain_name, offset - start_offset);
    }
    if ((n & 0b1100'0000) == 0b1100'0000) { // DNS compression
      if (offset >= dns_message_len) {
        return make_pair("", 0);
      }
      uint16_t new_offset =
          ((n & 0b0011'1111) << 8) | dns_message_base[offset++];
      if (new_offset >=
          start_offset) { // disallow forward jumps to avoid infinite loops
        return make_pair("", 0);
      }
      auto [suffix, suffix_bytes] =
          LoadDomainName(dns_message_base, dns_message_len, new_offset);
      if (suffix_bytes == 0) {
        return make_pair("", 0);
      }
      if (!domain_name.empty()) {
        domain_name += '.';
      }
      domain_name += suffix;
      return make_pair(domain_name, offset - start_offset);
    }
    if (offset + n > dns_message_len) {
      return make_pair("", 0);
    }
    if (!domain_name.empty()) {
      domain_name += '.';
    }
    domain_name.append((char *)dns_message_base + offset, n);
    offset += n;
  }
}

Str ToStr(Header::OperationCode code) {
  switch (code) {
  case Header::OperationCode::QUERY:
    return "QUERY";
  case Header::OperationCode::IQUERY:
    return "IQUERY";
  case Header::OperationCode::STATUS:
    return "STATUS";
  case Header::OperationCode::NOTIFY:
    return "NOTIFY";
  case Header::OperationCode::UPDATE:
    return "UPDATE";
  default:
    return f("UNKNOWN(%d)", code);
  }
}

void Header::write_to(string &buffer) {
  buffer.append((const char *)this, sizeof(*this));
}

Str Header::ToStr() const {
  Str r = "dns::Header {\n";
  r += "  id: " + f("0x%04hx", ntohs(id)) + "\n";
  r += "  reply: " + ::ToStr(reply) + "\n";
  r += "  opcode: " + Str(dns::ToStr(opcode)) + "\n";
  r += "  authoritative: " + ::ToStr(authoritative) + "\n";
  r += "  truncated: " + ::ToStr(truncated) + "\n";
  r += "  recursion_desired: " + ::ToStr(recursion_desired) + "\n";
  r += "  recursion_available: " + ::ToStr(recursion_available) + "\n";
  r += "  response_code: " + string(dns::ToStr(response_code)) + "\n";
  r += "  question_count: " + ::ToStr(question_count) + "\n";
  r += "  answer_count: " + ::ToStr(answer_count) + "\n";
  r += "  authority_count: " + ::ToStr(authority_count) + "\n";
  r += "  additional_count: " + ::ToStr(additional_count) + "\n";
  r += "}";
  return r;
}

struct SOA {
  string primary_name_server;
  string mailbox;
  uint32_t serial_number;
  uint32_t refresh_interval;
  uint32_t retry_interval;
  uint32_t expire_limit;
  uint32_t minimum_ttl;

  size_t LoadFrom(const char *ptr, size_t len, size_t offset) {
    size_t start_offset = offset;
    size_t loaded_size;
    tie(primary_name_server, loaded_size) = LoadDomainName(ptr, len, offset);
    if (loaded_size == 0) {
      return 0;
    }
    offset += loaded_size;
    tie(mailbox, loaded_size) = LoadDomainName(ptr, len, offset);
    if (loaded_size == 0) {
      return 0;
    }
    offset += loaded_size;
    if (offset + 20 > len) {
      return 0;
    }
    serial_number = ntohl(*(uint32_t *)(ptr + offset));
    offset += 4;
    refresh_interval = ntohl(*(uint32_t *)(ptr + offset));
    offset += 4;
    retry_interval = ntohl(*(uint32_t *)(ptr + offset));
    offset += 4;
    expire_limit = ntohl(*(uint32_t *)(ptr + offset));
    offset += 4;
    minimum_ttl = ntohl(*(uint32_t *)(ptr + offset));
    offset += 4;
    return offset - start_offset;
  }
  void write_to(string &buffer) const {
    buffer += EncodeDomainName(primary_name_server);
    buffer += EncodeDomainName(mailbox);
    uint32_t serial_number_big_endian = htonl(serial_number);
    buffer.append((char *)&serial_number_big_endian,
                  sizeof(serial_number_big_endian));
    uint32_t refresh_interval_big_endian = htonl(refresh_interval);
    buffer.append((char *)&refresh_interval_big_endian,
                  sizeof(refresh_interval_big_endian));
    uint32_t retry_interval_big_endian = htonl(retry_interval);
    buffer.append((char *)&retry_interval_big_endian,
                  sizeof(retry_interval_big_endian));
    uint32_t expire_limit_big_endian = htonl(expire_limit);
    buffer.append((char *)&expire_limit_big_endian,
                  sizeof(expire_limit_big_endian));
    uint32_t minimum_ttl_big_endian = htonl(minimum_ttl);
    buffer.append((char *)&minimum_ttl_big_endian,
                  sizeof(minimum_ttl_big_endian));
  }
};

size_t Question::LoadFrom(const char *ptr, size_t len, size_t offset) {
  size_t start_offset = offset;
  auto [loaded_name, loaded_size] = LoadDomainName(ptr, len, offset);
  if (loaded_size == 0) {
    return 0;
  }
  domain_name = loaded_name;
  offset += loaded_size;
  if (offset + 4 > len) {
    return 0;
  }
  type = Type(ntohs(*(uint16_t *)(ptr + offset)));
  offset += 2;
  class_ = Class(ntohs(*(uint16_t *)(ptr + offset)));
  offset += 2;
  return offset - start_offset;
}
void Question::write_to(string &buffer) const {
  string encoded = EncodeDomainName(domain_name);
  buffer.append(encoded);
  uint16_t type_big_endian = htons((uint16_t)type);
  buffer.append((char *)&type_big_endian, 2);
  uint16_t class_big_endian = htons((uint16_t)class_);
  buffer.append((char *)&class_big_endian, 2);
}
string Question::ToStr() const {
  return "dns::Question(" + domain_name + ", type=" + dns::ToStr(type) +
         ", class=" + Str(dns::ToStr(class_)) + ")";
}
string Question::to_html() const {
  return "<code class=dns-question>" + domain_name + " " + dns::ToStr(type) +
         "</code>";
}
size_t Record::LoadFrom(const char *ptr, size_t len, size_t offset) {
  size_t start_offset = offset;
  size_t base_size = Question::LoadFrom(ptr, len, offset);
  if (base_size == 0) {
    return 0;
  }
  offset += base_size;
  if (offset + 6 > len) {
    return 0;
  }
  expiration = chrono::steady_clock::now() +
               chrono::seconds(ntohl(*(uint32_t *)(ptr + offset))) +
               chrono::milliseconds(500);
  offset += 4;
  data_length = ntohs(*(uint16_t *)(ptr + offset));
  offset += 2;
  if (offset + data_length > len) {
    return 0;
  }
  if (type == Type::CNAME) {
    size_t limited_len = offset + data_length;
    auto [loaded_name, loaded_size] = LoadDomainName(ptr, limited_len, offset);
    if (loaded_size == 0) {
      return 0;
    }
    if (loaded_size != data_length) {
      return 0;
    }
    offset += data_length;
    // Re-encode domain name but without DNS compression
    data = EncodeDomainName(loaded_name);
    data_length = data.size();
  } else if (type == Type::SOA) {
    size_t limited_len = offset + data_length;
    SOA soa;
    size_t soa_len = soa.LoadFrom(ptr, limited_len, offset);
    if (soa_len != data_length) {
      return 0;
    }
    offset += data_length;
    // Re-encode SOA record but without DNS compression
    data = "";
    soa.write_to(data);
  } else {
    data = string((const char *)(ptr + offset), data_length);
    offset += data_length;
  }
  return offset - start_offset;
}
void Record::write_to(string &buffer) const {
  Question::write_to(buffer);
  uint32_t ttl_big_endian = htonl(ttl());
  buffer.append((char *)&ttl_big_endian, sizeof(ttl_big_endian));
  uint16_t data_length_big_endian = htons(data_length);
  buffer.append((char *)&data_length_big_endian,
                sizeof(data_length_big_endian));
  buffer.append(data);
}
uint32_t Record::ttl() const {
  if (expiration.has_value()) {
    auto d = duration_cast<chrono::seconds>(*expiration -
                                            chrono::steady_clock::now())
                 .count();
    return (uint32_t)max(d, 0l);
  } else {
    return (uint32_t)duration_cast<chrono::seconds>(kAuthoritativeTTL).count();
  }
}
Str Record::ToStr() const {
  return "dns::Record(" + Question::ToStr() + ", ttl=" + ::ToStr(ttl()) +
         ", data=\"" + BytesToHex(data) + "\")";
}
Str Record::pretty_value() const {
  if (type == Type::A) {
    if (data.size() == 4) {
      return ::ToStr((uint8_t)data[0]) + "." + ::ToStr((uint8_t)data[1]) + "." +
             ::ToStr((uint8_t)data[2]) + "." + ::ToStr((uint8_t)data[3]);
    }
  } else if (type == Type::CNAME) {
    auto [loaded_name, loaded_size] =
        LoadDomainName(data.data(), data.size(), 0);
    if (loaded_size == data.size()) {
      return loaded_name;
    }
  } else if (type == Type::SOA) {
    SOA soa;
    size_t parsed = soa.LoadFrom(data.data(), data.size(), 0);
    if (parsed == data.size()) {
      return f("%s %s %d %d %d %d %d", soa.primary_name_server.c_str(),
               soa.mailbox.c_str(), soa.serial_number, soa.refresh_interval,
               soa.retry_interval, soa.expire_limit, soa.minimum_ttl);
    }
  }
  return BytesToHex(data);
}
Str Record::to_html() const {
  return "<code class=dns-record title=TTL=" + ::ToStr(ttl()) +
         "s style=display:inline-block>" + domain_name + " " +
         dns::ToStr(type) + " " + pretty_value() + "</code>";
}

void Message::Parse(const char *ptr, size_t len, string &err) {
  if (len < sizeof(Header)) {
    err = "DNS message buffer is too short: " + ::ToStr(len) +
          " bytes. DNS header requires at least 12 bytes. Hex-escaped "
          "buffer: " +
          BytesToHex(ptr, len);
    return;
  }
  header = *(Header *)ptr;

  size_t offset = sizeof(Header);

  for (int i = 0; i < header.question_count.Get(); ++i) {
    if (auto q_size = questions.emplace_back().LoadFrom(ptr, len, offset)) {
      offset += q_size;
    } else {
      err = "Failed to load DNS question from " + BytesToHex(ptr, len);
      return;
    }
  }

  auto LoadRecordList = [&](Vec<Record> &v, U16 n) {
    for (int i = 0; i < n; ++i) {
      Record &r = v.emplace_back();
      if (auto r_size = r.LoadFrom(ptr, len, offset)) {
        offset += r_size;
      } else {
        v.pop_back();
        err = "Failed to load a record from DNS message. Loaded part: \n" +
              this->ToStr() + "\nFull message:\n" + BytesToHex(ptr, len) +
              "\nFailed when parsing:\n" +
              BytesToHex(ptr + offset, len - offset);
        return;
      }
    }
  };

  LoadRecordList(answers, header.answer_count);
  if (!err.empty())
    return;
  LoadRecordList(authority, header.authority_count);
  if (!err.empty())
    return;
  LoadRecordList(additional, header.additional_count);
  if (!err.empty())
    return;
}
Str Message::ToStr() const {
  Str r = "dns::Message {\n";
  r += IndentString(header.ToStr()) + "\n";
  for (auto &q : questions) {
    r += "  " + q.ToStr() + "\n";
  }
  for (const Record &a : answers) {
    r += "  " + a.ToStr() + "\n";
  }
  for (const Record &a : authority) {
    r += "  " + a.ToStr() + "\n";
  }
  for (const Record &a : additional) {
    r += "  " + a.ToStr() + "\n";
  }
  r += "}";
  return r;
}
void Message::ForEachRecord(Fn<void(const Record &)> f) const {
  for (const Record &r : answers) {
    f(r);
  }
  for (const Record &r : authority) {
    f(r);
  }
  for (const Record &r : additional) {
    f(r);
  }
}

} // namespace maf::dns