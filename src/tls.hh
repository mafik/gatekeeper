#pragma once

#include "arr.hh"
#include "optional.hh"
#include "span.hh"
#include "stream.hh"
#include "tcp.hh"
#include "unique_ptr.hh"

// Bare-minimum TLS 1.3 implementation.
//
// Doesn't check peer certificates (can be MITM-ed).
//
// Not compliant with RFC 8446 due to lack of several features:
// - TLS_AES_128_GCM_SHA256 cipher
// - rsa_pkcs1_sha256 signatures
// - rsa_pss_rsae_sha256 signatures
// - ecdsa_secp256r1_sha256 signatures
// - secp256r1 key exchange
// - TLS Cookies
namespace maf::tls {

struct Connection;
struct RecordHeader;

// Responsible for data & logic specific to a single phase of TLS.
struct Phase {
  Connection &conn;

  Phase(Connection &conn);
  virtual ~Phase() = default;

  virtual void ProcessRecord(RecordHeader &) = 0;
  virtual void PhaseSend() = 0;
};

void HKDF_Expand_Label(Span<> key, StrView label, Span<> ctx, Span<> out);

struct Connection : Stream {
  struct TCP_Connection : tcp::Connection {
    void NotifyReceived() override;
    void NotifyClosed() override;
    const char *Name() const override;
  };

  TCP_Connection tcp_connection;

  UniquePtr<Phase> phase;

  struct Config : public tcp::Connection::Config {
    Optional<Str> server_name;
  };

  void Connect(Config);

  // Encrypt & send the contents of `send_tls`.
  void Send() override;

  void Close() override;

  operator Status &() override { return tcp_connection; }
};

} // namespace maf::tls