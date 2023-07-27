// CLI program for signing text with Ed25519.

#include "hex.hh"
#pragma maf main

#include <iostream>

#include "ed25519.hh"
#include "log.hh"
#include "ssh_key.hh"
#include "vec.hh"

using namespace maf;

#pragma maf add run argument "~/.ssh/id_ed25519"

int main(int argc, char *argv[]) {
  if (argc != 3) {
    FATAL << "Missing argumemt: path to private key file";
  }
  Path path(argv[1]);
  Status status;
  auto key = SSHKey::FromFile(path, status);

  if (not OK(status)) {
    FATAL << "Failed to read key: " << status;
  }

  Str message;
  Vec<char> buffer(4096);
  auto rdbuf = std::cin.rdbuf();
  while (auto cnt_char = rdbuf->sgetn(buffer.data(), 4096))
    message.insert(message.end(), buffer.data(), buffer.data() + cnt_char);

  auto signature = ed25519::Signature(message, key.private_key, key.public_key);
  LOG << BytesToHex(signature.bytes);
  return 0;
}