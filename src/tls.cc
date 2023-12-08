#include "tls.hh"

#include <cstring>
#include <initializer_list>

#include "aead_chacha20_poly1305.hh"
#include "big_endian.hh"
#include "curve25519.hh"
#include "format.hh"
#include "hex.hh"
#include "hkdf.hh"
#include "int.hh"
#include "log.hh"
#include "poly1305.hh"
#include "sha.hh"
#include "span.hh"
#include "status.hh"

namespace maf::tls {

// Nice introduction to TLS 1.3: https://tls13.xargs.org/

struct RecordHeader {
  U8 type;
  U8 version_major;
  U8 version_minor;
  Big<U16> length;
  char contents[0];

  void Validate(Status &status) {
    if (version_major != 3) {
      status() += "TLS Record Header major version is " + ToStr(version_major) +
                  " but expected 3";
      return;
    }
    if (version_minor != 1 && version_minor != 3 && version_minor != 4) {
      status() += "TLS Record Header minor version is " + ToStr(version_minor) +
                  " but expected 3 (TLS 1.2) or 4 (TLS 1.3)";
      return;
    }
  }

  operator Span<>() { return {(char *)this, sizeof(*this)}; }
  Span<> Contents() { return {contents, length.Get()}; }
};

static_assert(sizeof(RecordHeader) == 5,
              "tls::RecordHeader should have 5 bytes");

void HKDF_Expand_Label(Span<> key, StrView label, Span<> ctx, Span<> out) {
  Vec<> hkdf_label;
  hkdf_label.Append(Big<U16>(out.size()));
  hkdf_label.push_back(label.size());
  hkdf_label.insert(hkdf_label.end(), label.begin(), label.end());
  hkdf_label.push_back(ctx.size());
  hkdf_label.insert(hkdf_label.end(), ctx.begin(), ctx.end());
  HKDF_Expand<SHA256>(key, hkdf_label, out);
}

Arr<char, 32> zero_key = {};
SHA256 early_secret = HKDF_Extract<SHA256>(Span<>("\x00", 1), zero_key);
SHA256 empty_hash(kEmptySpan);
Arr<char, 6> kClientChangeCipherSpec = HexArr("140303000101");

static void XorIV(Arr<char, 12> &iv, U64 counter) {
  for (int i = 0; i < sizeof(counter); ++i) {
    iv[11 - i] ^= (counter >> (i * 8)) & 0xff;
  }
}

// Responsible for encrypting & decrypting TLS records
struct RecordWrapper {
  Arr<char, 32> key;
  Arr<char, 12> iv;
  U64 counter = 0;

  // Constructs uninitialized RecordWrapper
  RecordWrapper() = default;

  RecordWrapper(Span<char, 32> secret) {
    HKDF_Expand_Label(secret, "tls13 key", kEmptySpan, key);
    HKDF_Expand_Label(secret, "tls13 iv", kEmptySpan, iv);
  }

  void Wrap(Vec<> &buf, U8 record_type, std::function<void()> wrapped) {
    Size header_begin = buf.size();
    buf.insert(buf.end(), {0x17, 0x03, 0x03, 0x00,
                           0x00}); // application data, TLS 1.2, length
    Size header_end = buf.size();
    Size record_length_offset = buf.size() - 2;
    Size record_begin = buf.size();
    wrapped();
    buf.push_back(record_type);
    Size record_end = buf.size();
    Size tag_begin = buf.size();
    buf.insert(buf.end(), 16, 0); // Poly1305 tag
    Size tag_end = buf.size();
    buf.Span()
        .RemovePrefix(record_length_offset)
        .PutRef(Big<U16>(tag_end - record_begin));
    XorIV(iv, counter);
    auto data = Span<>(buf.begin() + record_begin, buf.begin() + record_end);
    auto aad = Span<>(buf.begin() + header_begin, buf.begin() + header_end);
    auto tag = Encrypt_AEAD_CHACHA20_POLY1305(key, iv, data, aad);
    XorIV(iv, counter);
    ++counter;
    memcpy(buf.data() + tag_begin, tag.bytes, 16);
  }

  bool Unwrap(RecordHeader &record, Span<> &data, U8 &true_type) {
    auto contents = record.Contents();
    Poly1305 tag(contents.last<16>());
    data = contents.first(contents.size() - 16);
    XorIV(iv, counter);
    bool decrypted_ok =
        Decrypt_AEAD_CHACHA20_POLY1305(key, iv, data, record, tag);
    XorIV(iv, counter);
    ++counter;
    if (decrypted_ok) {
      true_type = data.back();
      data = data.first(data.size() - 1);
    }
    return decrypted_ok;
  }
};

StrView AlertLevelToStr(U8 level) {
  switch (level) {
  case 1:
    return "warning";
  case 2:
    return "fatal";
  default:
    return "unknown";
  }
}

StrView AlertDescriptionToStr(U8 desc) {
  switch (desc) {
  case 0:
    return "close_notify";
  case 10:
    return "unexpected_message";
  case 20:
    return "bad_record_mac";
  case 21:
    return "decryption_failed";
  case 22:
    return "record_overflow";
  case 30:
    return "decompression_failure";
  case 40:
    return "handshake_failure";
  case 41:
    return "no_certificate";
  case 42:
    return "bad_certificate";
  case 43:
    return "unsupported_certificate";
  case 44:
    return "certificate_revoked";
  case 45:
    return "certificate_expired";
  case 46:
    return "certificate_unknown";
  case 47:
    return "illegal_parameter";
  case 48:
    return "unknown_ca";
  case 49:
    return "access_denied";
  case 50:
    return "decode_error";
  case 51:
    return "decrypt_error";
  case 60:
    return "export_restriction";
  case 70:
    return "protocol_version";
  case 71:
    return "insufficient_security";
  case 80:
    return "internal_error";
  case 86:
    return "inappropriate_fallback";
  case 90:
    return "user_canceled";
  case 100:
    return "no_renegotiation";
  case 110:
    return "unsupported_extension";
  case 111:
    return "certificate_unobtainable";
  case 112:
    return "unrecognized_name";
  case 113:
    return "bad_certificate_status_response";
  case 114:
    return "bad_certificate_hash_value";
  case 115:
    return "unknown_psk_identity";
  case 116:
    return "certificate_required";
  case 117:
    return "no_application_protocol";
  default:
    return "unknown";
  }
}

Phase::Phase(Connection &conn) : conn(conn) {}

// Phase for the encrypted application part (after "Client/Server Handshake
// Finished").
struct Phase3 : Phase {
  RecordWrapper server_wrapper;
  RecordWrapper client_wrapper;

  Phase3(Connection &conn, SHA256 handshake_secret, SHA256 handshake_hash)
      : Phase(conn) {
    Arr<char, 32> derived, client_secret, server_secret; // Hash-size-bytes
    HKDF_Expand_Label(handshake_secret, "tls13 derived", empty_hash, derived);
    auto master_secret = HKDF_Extract<SHA256>(derived, zero_key);
    HKDF_Expand_Label(master_secret, "tls13 c ap traffic", handshake_hash,
                      client_secret);
    HKDF_Expand_Label(master_secret, "tls13 s ap traffic", handshake_hash,
                      server_secret);
    server_wrapper = RecordWrapper(server_secret);
    client_wrapper = RecordWrapper(client_secret);
  }

  void ProcessRecord(RecordHeader &record) override {
    if (record.type != 23) {
      AppendErrorMessage(conn) +=
          f("Received TLS record type %d but expected 23 "
            "(Application Data Record)",
            record.type);
      return;
    }
    Span<> data;
    U8 true_type;
    if (!server_wrapper.Unwrap(record, data, true_type)) {
      AppendErrorMessage(conn) += "Couldn't decrypt TLS record";
      return;
    }

    if (true_type == 21) { // Alert
      if (data.size() != 2) {
        AppendErrorMessage(conn) +=
            f("Received TLS Alert with length %d but expected 2", data.size());
        return;
      }
      U8 level = data[0];
      if (level == 1) {
        // Ignore warnings
      } else {
        U8 description = data[1];
        Str &msg = AppendErrorMessage(conn);
        msg += "Received ";
        msg += AlertLevelToStr(level);
        msg += " TLS Alert: ";
        msg += AlertDescriptionToStr(description);
        return;
      }
    } else if (true_type == 22) { // Handshake
      return;                     // Ignore because we don't use tickets anyway
    } else if (true_type == 23) { // Application Data
      conn.inbox.insert(conn.inbox.end(), data.begin(), data.end());
      conn.NotifyReceived();
    } else {
      AppendErrorMessage(conn) +=
          f("Received unknown TLS record type %d", true_type);
    }
  }

  void PhaseSend() override {
    client_wrapper.Wrap(conn.tcp_connection.outbox, 0x17, [&]() {
      conn.tcp_connection.outbox.insert(conn.tcp_connection.outbox.end(),
                                        conn.outbox.begin(), conn.outbox.end());
    });
    conn.tcp_connection.Send();
  }
};

// Phase for the encrypted handshake part (between "Server Hello" & "Server
// Handshake Finished").
struct Phase2 : Phase {
  SHA256::Builder handshake_hash_builder;
  SHA256 handshake_secret;
  Arr<char, 32> client_secret;
  RecordWrapper server_wrapper;
  RecordWrapper client_wrapper;
  bool send_tls_requested;

  Phase2(Connection &conn, SHA256::Builder sha_builder,
         curve25519::Shared shared_secret, bool send_tls_requested)
      : Phase(conn), handshake_hash_builder(std::move(sha_builder)),
        send_tls_requested(send_tls_requested) {
    auto hello_hash_builder = handshake_hash_builder;
    auto hello_hash = hello_hash_builder.Finalize();
    Arr<char, 32> derived, server_secret; // Hash-size-bytes

    HKDF_Expand_Label(early_secret, "tls13 derived", empty_hash, derived);
    handshake_secret = HKDF_Extract<SHA256>(derived, shared_secret);
    HKDF_Expand_Label(handshake_secret, "tls13 c hs traffic", hello_hash,
                      client_secret);
    HKDF_Expand_Label(handshake_secret, "tls13 s hs traffic", hello_hash,
                      server_secret);
    server_wrapper = RecordWrapper(server_secret);
    client_wrapper = RecordWrapper(client_secret);
  }

  void ProcessRecord(RecordHeader &record) override {
    auto type = record.type;
    if (type == 20) { // Change Cipher Spec - ignore
      return;
    }
    if (type != 23) { // Application Data
      AppendErrorMessage(conn) += f("Received TLS record type %d", type);
      return;
    }
    Span<> data;
    U8 true_type;
    if (!server_wrapper.Unwrap(record, data, true_type)) {
      AppendErrorMessage(conn) += "Couldn't decrypt TLS record";
      return;
    }

    if (true_type != 22) { // Handshake
      AppendErrorMessage(conn) +=
          f("Received TLS record type %d but expected 22 (Handshake Record)",
            true_type);
      return;
    }
    handshake_hash_builder.Update(data);

    while (!data.empty()) {
      U8 handshake_type = data.Consume<U8>();
      U24 handshake_length = data.Consume<Big<U24>>();
      if (handshake_length > data.size()) {
        AppendErrorMessage(conn) +=
            "TLS handshake failed because of record with invalid length";
        return;
      }
      auto handshake_data = data.subspan(0, handshake_length);
      data = data.subspan(handshake_length);

      if (handshake_type == 8) {
        // "Server Encrypted Extensions"
      } else if (handshake_type == 11) {
        // "Server Certificate"
      } else if (handshake_type == 15) {
        // "Server Certificate Verify"
      } else if (handshake_type == 20) {
        // "Server Handshake Finished"
        auto handshake_hash = handshake_hash_builder.Finalize();

        conn.tcp_connection.outbox.insert(conn.tcp_connection.outbox.end(),
                                          kClientChangeCipherSpec.begin(),
                                          kClientChangeCipherSpec.end());

        client_wrapper.Wrap(conn.tcp_connection.outbox, 0x16, [&]() {
          Arr<char, 32> finished_key; // Hash-size-bytes
          HKDF_Expand_Label(client_secret, "tls13 finished", kEmptySpan,
                            finished_key);
          SHA256 verify_data = HMAC<SHA256>(finished_key, handshake_hash);
          auto &buf = conn.tcp_connection.outbox;
          buf.push_back(0x14); // handshake
          buf.Append(Big<U24>(32));
          buf.insert(buf.end(), verify_data.bytes, verify_data.bytes + 32);
        });

        bool send_tls_requested =
            this->send_tls_requested; // copy to avoid use-after-free
        Connection &conn2 = conn;
        conn2.phase.reset(new Phase3(conn2, handshake_secret, handshake_hash));
        if (send_tls_requested) {
          // Encrypt contents of `send_tls` and send it along with `Client
          // Verify`.
          conn2.phase->PhaseSend();
        } else {
          conn2.tcp_connection.Send();
        }
      } else {
        AppendErrorMessage(conn) +=
            f("TLS handshake failed because of unknown message type %d",
              handshake_type);
        return;
      }
    }
  }

  void PhaseSend() override { send_tls_requested = true; }
};

// Phase for the plaintext handshake part (before "Server Hello").
struct Phase1 : Phase {
  SHA256::Builder sha_builder;
  curve25519::Private client_secret;
  bool send_tls_requested = false;

  Phase1(Connection &conn, Connection::Config &config) : Phase(conn) {
    client_secret = curve25519::Private::FromDevUrandom(conn);
    if (!OK(conn)) {
      AppendErrorMessage(conn) += "Couldn't generate private key for TLS";
      conn.tcp_connection.Close();
      return;
    }
    SendClientHello(config);
  }

  void SendClientHello(Connection::Config &config) {
    constexpr bool kCompatibleWithTLS12 = false;
    auto &send_tcp = conn.tcp_connection.outbox;
    // Generate encryption keys.
    auto client_public = curve25519::Public::FromPrivate(client_secret);

    // Send "Client Hello"
    auto Append = [&](const std::initializer_list<char> bytes) {
      send_tcp.insert(send_tcp.end(), bytes);
    };
    Append({0x16}); // handshake
    if constexpr (kCompatibleWithTLS12) {
      Append({0x03, 0x01}); // protocol verison: TLS 1.0 (for compatibility)
    } else {
      Append({0x03, 0x04}); // protocol verison: TLS 1.3
    }
    Size record_length_offset = send_tcp.size();
    Append({0x00, 0x00}); // placeholder for record length
    Size record_begin = send_tcp.size();
    Append({0x01}); // handshake type: Client Hello
    Size handshake_length_offset = send_tcp.size();
    Append({0x00, 0x00, 0x00}); // placeholder for handshake length
    Size handshake_begin = send_tcp.size();
    if constexpr (kCompatibleWithTLS12) {
      Append({0x03, 0x03}); // client version: TLS 1.2 (for compatibility)
    } else {
      Append({0x03, 0x04}); // client version: TLS 1.3
    }

    for (int i = 0; i < 32; ++i) {
      send_tcp.push_back(rand() % 0x100); // client random
    }

    if constexpr (kCompatibleWithTLS12) {
      Append({0x20}); // session id length: 32
      for (int i = 0; i < 32; ++i) {
        send_tcp.push_back(rand() % 0x100); // fake session id
      }
    } else {
      Append({0});
    }

    if constexpr (kCompatibleWithTLS12) {
      Append({0x00, 0x08}); // cipher suites length: 2 (one cipher suite)
      Append({0x13, 0x03}); // TLS_CHACHA20_POLY1305_SHA256
      Append({0x13, 0x01}); // TLS_AES_128_GCM_SHA256
      Append({0x13, 0x02}); // TLS_AES_256_GCM_SHA384
      Append({0x00, 0xff}); // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    } else {
      Append({0x00, 0x02}); // cipher suites length: 2 (one cipher suite)
      Append({0x13, 0x03}); // TLS_CHACHA20_POLY1305_SHA256
    }

    Append({0x01}); // compression methods length: 1
    Append({0x00}); // compression method: null

    Size extensions_length_offset = send_tcp.size();
    Append({0x00, 0x00}); // placeholder for extensions length
    Size extensions_begin = send_tcp.size();

    if (config.server_name) {
      auto hostname_length = config.server_name->size();
      auto entry_length = hostname_length + 3;
      auto extension_length = entry_length + 2;
      Append({0x00, 0x00}); // extension type: server name
      send_tcp.Append(Big<U16>(extension_length));
      send_tcp.Append(Big<U16>(entry_length));
      Append({0x00}); // entry type: DNS hostname
      send_tcp.Append(Big<U16>(hostname_length));
      send_tcp.insert(send_tcp.end(), config.server_name->begin(),
                      config.server_name->end());
    }

    if constexpr (kCompatibleWithTLS12) {
      Append({0x00, 0x0b}); // extension type: EC point formats
      Append({0x00, 0x04}); // extension length: 4
      Append({0x03});       // format length: 3
      Append({0x00});       // format: uncompressed
      Append({0x01});       // format: ansiX962_compressed_prime
      Append({0x02});       // format: ansiX962_compressed_char2
    }

    Append({0x00, 0x0a}); // extension type: supported groups
    if constexpr (kCompatibleWithTLS12) {
      Append({0x00, 0x16}); // extension length: 22
      Append({0x00, 0x14}); // supported groups length: 20
      Append({0x00, 0x1d}); // x25519
      Append({0x00, 0x17}); // secp256r1
      Append({0x00, 0x1e}); // x448
      Append({0x00, 0x19}); // secp521r1
      Append({0x00, 0x18}); // secp384r1
      Append({0x01, 0x00}); // ffdhe2048
      Append({0x01, 0x01}); // ffdhe3072
      Append({0x01, 0x02}); // ffdhe4096
      Append({0x01, 0x03}); // ffdhe6144
      Append({0x01, 0x04}); // ffdhe8192
    } else {
      Append({0x00, 0x04}); // extension length: 4
      Append({0x00, 0x02}); // supported groups length: 2
      Append({0x00, 0x1d}); // x25519
    }

    Append({0x00, 0x23}); // extension type: session ticket
    Append({0x00, 0x00}); // extension length: 0

    Append({0x00, 0x16}); // extension type: entrypt then MAC
    Append({0x00, 0x00}); // extension length: 0

    Append({0x00, 0x17}); // extension type: extended master secret
    Append({0x00, 0x00}); // extension length: 0

    Append({0x00, 0x0d}); // extension type: signature algorithms
    Append({0x00, 0x1e}); // extension length: 30
    Append({0x00, 0x1c}); // signature algorithms length: 28
    Append({0x08, 0x07}); // ED25519
    Append({0x04, 0x03}); // ECDSA-SECP256r1-SHA256
    Append({0x05, 0x03}); // ECDSA-SECP384r1-SHA384
    Append({0x06, 0x03}); // ECDSA-SECP521r1-SHA512
    Append({0x08, 0x08}); // ED448
    Append({0x08, 0x09}); // RSA-PSS-PSS-SHA256
    Append({0x08, 0x0a}); // RSA-PSS-PSS-SHA384
    Append({0x08, 0x0b}); // RSA-PSS-PSS-SHA512
    Append({0x08, 0x04}); // RSA-PSS-RSAE-SHA256
    Append({0x08, 0x05}); // RSA-PSS-RSAE-SHA384
    Append({0x08, 0x06}); // RSA-PSS-RSAE-SHA512
    Append({0x04, 0x01}); // RSA-PKCS1-SHA256
    Append({0x05, 0x01}); // RSA-PKCS1-SHA384
    Append({0x06, 0x01}); // RSA-PKCS1-SHA512

    Append({0x00, 0x2b}); // extension type: supported versions
    Append({0x00, 0x03}); // extension length: 3
    Append({0x02});       // supported versions length: 2
    Append({0x03, 0x04}); // TLS 1.3

    Append({0x00, 0x2d}); // extension type: PSK key exchange modes
    Append({0x00, 0x02}); // extension length: 2
    Append({0x01});       // PSK key exchange modes length: 1
    Append({0x01});       // PSK key exchange mode: PSK with (EC)DHE

    Append({0x00, 0x33}); // extension type: key share
    Append({0x00, 0x26}); // extension length: 38
    Append({0x00, 0x24}); // key share length: 36
    Append({0x00, 0x1d}); // x25519
    Append({0x00, 0x20}); // public key length: 32
    send_tcp.insert(send_tcp.end(), client_public.bytes.begin(),
                    client_public.bytes.end());

    send_tcp.Span()
        .RemovePrefix(extensions_length_offset)
        .PutRef(Big<U16>(send_tcp.size() - extensions_begin));
    send_tcp.Span()
        .RemovePrefix(handshake_length_offset)
        .PutRef(Big<U24>(send_tcp.size() - handshake_begin));
    send_tcp.Span()
        .RemovePrefix(record_length_offset)
        .PutRef(Big<U16>(send_tcp.size() - record_begin));

    sha_builder.Update(Span<>((char *)&send_tcp[record_begin],
                              send_tcp.size() - record_begin));

    conn.tcp_connection.Send();
  }

  void ProcessHandshake(Connection &conn, Span<> handshake) {
    Span<> server_hello = handshake;
    U8 handshake_type = server_hello.Consume<U8>();
    U24 handshake_length = server_hello.Consume<Big<U24>>();
    if (handshake_length > server_hello.size()) {
      AppendErrorMessage(conn) +=
          f("TLS Handshake Header claims length %d but there are "
            "only %d bytes left in the record",
            handshake_length, server_hello.size());
      return;
    }
    if (handshake_type != 2) {
      AppendErrorMessage(conn) +=
          f("Received TLS handshake type %d but expected 2 "
            "(Server Hello)",
            handshake_type);
      return;
    }

    U8 server_version_major = server_hello.Consume<U8>();
    U8 server_version_minor = server_hello.Consume<U8>();
    server_hello = server_hello.subspan<32>(); // server random
    U8 session_id_length = server_hello.Consume<U8>();
    server_hello = server_hello.subspan(session_id_length);
    U16 cipher_suite = server_hello.Consume<Big<U16>>();
    U8 compression_method = server_hello.Consume<U8>();
    U16 extensions_length = server_hello.Consume<Big<U16>>();
    if (extensions_length != server_hello.size()) {
      AppendErrorMessage(conn) +=
          "Server hello extensions_length is " + ToStr((U32)extensions_length) +
          " but there are still " + ToStr(server_hello.size()) + " bytes left";
      return;
    }

    // If extension is missing we generously provide correct value.
    U8 supported_version_major = 3;
    U8 supported_version_minor = 4;
    curve25519::Public server_public;

    while (!server_hello.empty()) {
      U16 extension_type = server_hello.Consume<Big<U16>>();
      U16 extension_length = server_hello.Consume<Big<U16>>();
      if (extension_length > server_hello.size()) {
        AppendErrorMessage(conn) +=
            f("Server hello extension_length is %d but there are "
              "only %d bytes left",
              extension_length, server_hello.size());
        return;
      }
      Span<> extension_data = server_hello.first(extension_length);
      server_hello = server_hello.subspan(extension_length);
      switch (extension_type) {
      case 0x2b: // supported_versions
        supported_version_major = extension_data.Consume<U8>();
        supported_version_minor = extension_data.Consume<U8>();
        break;
      case 0x33: { // key share
        U16 group = extension_data.Consume<Big<U16>>();
        U16 length = extension_data.Consume<Big<U16>>();
        if (length != extension_data.size()) {
          AppendErrorMessage(conn) += f(
              "Server Hello key share length is %d but there are %d bytes left",
              length, extension_data.size());
          return;
        }
        switch (group) {
        case 0x1d: { // x25519
          if (length != 32) {
            AppendErrorMessage(conn) +=
                f("Server Hello key share group is x25519 but "
                  "length is %d instead of 32",
                  length);
            return;
          }
          memcpy(server_public.bytes.data(), extension_data.data(), 32);
          break;
        }
        default: {
          AppendErrorMessage(conn) +=
              f("Server Hello key share group is %d but only "
                "x25519 is supported",
                group);
          return;
        }
        }
        break;
      }
      } // switch (extension_type)
    } // while (!server_hello.empty())

    sha_builder.Update(handshake);
    curve25519::Shared shared_secret =
        curve25519::Shared::FromPrivateAndPublic(client_secret, server_public);

    conn.phase.reset(new Phase2(conn, std::move(sha_builder), shared_secret,
                                send_tls_requested));
  }

  void ProcessRecord(RecordHeader &record) override {
    if (record.type == 0x16) { // handshake
      ProcessHandshake(conn, record.Contents());
    } else {
      AppendErrorMessage(conn) +=
          f("Received TLS record type %d but expected 22 "
            "(TLS Handshake)",
            record.type);
    }
  }

  void PhaseSend() override { send_tls_requested = true; }
};

void Connection::Connect(Config config) {
  tcp_connection.Connect(config);

  phase.reset(new Phase1(*this, config));
}

void Connection::Send() { phase->PhaseSend(); }

void Connection::Close() { tcp_connection.Close(); }

Size ConsumeRecord(Connection &conn) {
  Vec<> &received_tcp = conn.tcp_connection.inbox;
  if (received_tcp.size() < 5) {
    return 0; // wait for more data
  }
  RecordHeader &record_header = *(RecordHeader *)received_tcp.data();
  record_header.Validate(conn);
  if (!OK(conn)) {
    AppendErrorMessage(conn) += "TLS stream corrupted";
    return 0;
  }
  Size record_size = sizeof(RecordHeader) + record_header.length.Get();
  if (received_tcp.size() < record_size) {
    return 0; // wait for more data
  }
  conn.phase->ProcessRecord(record_header);
  return record_size;
}

tls::Connection &Upcast(tls::Connection::TCP_Connection &tcp_connection) {
  return *(tls::Connection *)(((uintptr_t)&tcp_connection) -
                              offsetof(tls::Connection, tcp_connection));
}

void Connection::TCP_Connection::NotifyReceived() {
  // Get the pointer to the Connection object from the pointer to the
  // TCP_Connection
  tls::Connection &conn = Upcast(*this);
  while (true) {
    Size n = ConsumeRecord(conn);
    if (IsClosed()) {
      return;
    }
    if (!OK(conn)) {
      ERROR << f("%p ", &conn) << ErrorMessage(conn);
      conn.Close();
      return;
    }
    if (n == 0) {
      return;
    }
    inbox.erase(inbox.begin(), inbox.begin() + n);
  }
}

void Connection::TCP_Connection::NotifyClosed() {
  tls::Connection &conn = Upcast(*this);
  conn.NotifyClosed();
}

const char *Connection::TCP_Connection::Name() const {
  return "tls::Connection::TCP_Connection";
}

} // namespace maf::tls