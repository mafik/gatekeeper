#include "ssh_key.hh"

#include "base64.hh"
#include "big_endian.hh"
#include "span.hh"
#include "status.hh"
#include "virtual_fs.hh"
#include <cstring>
#include <string>

namespace maf {

SSHKey SSHKey::FromFile(const Path &path, Status &status) {
  Vec<> decoded;
  fs::Map(
      fs::real, path,
      [&](StrView contents) {
        static constexpr StrView kSshKeyPrefix =
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"sv;
        static constexpr StrView kSshKeySuffix =
            "\n-----END OPENSSH PRIVATE KEY-----\n"sv;
        if (!contents.starts_with(kSshKeyPrefix)) {
          auto &err = AppendErrorMessage(status);
          err = "Key at ";
          err += StrView(path);
          err += " should start with \"";
          err += kSshKeyPrefix;
          err += "\"";
          return;
        }
        contents.remove_prefix(kSshKeyPrefix.size());
        size_t end_pos = contents.find(kSshKeySuffix);
        if (end_pos == StrView::npos) {
          auto &err = AppendErrorMessage(status);
          err = "Key at ";
          err += StrView(path);
          err += " should end with \"";
          err += kSshKeySuffix;
          err += "\"";
          return;
        }
        contents.remove_suffix(contents.size() - end_pos);
        decoded = Base64Decode(contents);
      },
      status);
  if (not OK(status)) {
    return {};
  }
  Span<> buf = decoded;
  static constexpr auto kSshKeyMagic = SpanOfCStr("openssh-key-v1\0");
  if (!buf.StartsWith(kSshKeyMagic)) {
    AppendErrorMessage(status) +=
        "Key at " + Str(path) +
        " doesn't start with \"openssh-key-v1\\0\" magic bytes";
    return {};
  }
  buf = buf.subspan(kSshKeyMagic.size());
  auto ConsumeSizedSpan = [&](Span<> &buf_arg) -> Span<> {
    U32 len = buf_arg.Consume<Big<U32>>();
    Span<> ret = buf_arg.subspan(0, len);
    buf_arg.RemovePrefix(len);
    return ret;
  };
  StrView cipher_name = StrViewOf(ConsumeSizedSpan(buf));
  StrView kdf_name = StrViewOf(ConsumeSizedSpan(buf));
  Span<> kdf = ConsumeSizedSpan(buf);
  U32 num_keys = buf.Consume<Big<U32>>();
  if (num_keys != 1) {
    AppendErrorMessage(status) += "Key at " + Str(path) +
                                  " should have exactly one key, got " +
                                  ToStr(num_keys);
    return {};
  }
  for (int i_key = 0; i_key < num_keys; ++i_key) {
    SSHKey k;
    Span<> pub = ConsumeSizedSpan(buf);
    Span<> priv = ConsumeSizedSpan(buf);

    // Parse `priv`
    U32 check1 = priv.Consume<Big<U32>>();
    U32 check2 = priv.Consume<Big<U32>>();
    StrView key_type = StrViewOf(ConsumeSizedSpan(priv));
    if (key_type == "ssh-ed25519"sv) {
      Span<> pub0 = ConsumeSizedSpan(priv);
      if (pub0.size() != 32) {
        AppendErrorMessage(status) +=
            "Public key for Ed25519 key at " + Str(path) +
            " should be 32 bytes long, got " + ToStr(pub0.size());
        return {};
      }
      memcpy(k.public_key.bytes, pub0.data(), 32);
      Span<> priv0 = ConsumeSizedSpan(priv);
      if (priv0.size() != 64) {
        AppendErrorMessage(status) +=
            "Private key for Ed25519 key at " + Str(path) +
            " should be 64 bytes long, got " + ToStr(priv0.size());
        return {};
      }
      // The private key is actually a concatenation of private+public. Each of
      // them 32-bytes long. We copy out only the private part.
      memcpy(k.private_key.bytes, priv0.data(), 32);
      k.comment = StrViewOf(ConsumeSizedSpan(priv));
      return k;
    } else {
      AppendErrorMessage(status) += "Unknown key type: " + Str(key_type);
      return {};
    }

    // There is some padding here that could be verified but we don't care.
    // The padding should be right-trimmed subspan of 01:02:03:04:05:06:07:08.
  }
  return {};
}

} // namespace maf