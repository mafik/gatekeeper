// CLI program for signing ELF files.

#pragma maf main

#include <cstring>

#include "ed25519.hh"
#include "elf.hh"
#include "log.hh"
#include "path.hh"
#include "ssh_key.hh"
#include "virtual_fs.hh"

using namespace maf;

int main(int argc, char *argv[]) {
  if (argc != 4) {
    LOG << "Usage: " << argv[0] << " <private key> <input ELF> <output ELF>";
    return 1;
  }
  Status status;
  auto key = SSHKey::FromFile(argv[1], status);
  if (not OK(status)) {
    FATAL << "Failed to read key: " << status;
  }
  Str elf_copy;
  ReadFile(
      argv[2], [&](StrView elf_contents) { elf_copy = Str(elf_contents); },
      status);
  if (not OK(status)) {
    FATAL << "Failed to read ELF file: " << status;
  }
  auto signature =
      ed25519::Signature(elf_copy, key.private_key, key.public_key);
  auto sig_section = elf::FindSection(elf_copy, "maf.sig.ed25519", status);
  if (not OK(status)) {
    FATAL << "Failed to find signature section: " << status;
  }
  if (sig_section.size() != sizeof(signature.bytes)) {
    FATAL << "Invalid signature section size: " << sig_section.size();
  }
  memcpy(sig_section.data(), signature.bytes, sizeof(signature.bytes));
  WriteFile(argv[3], elf_copy, status, 0775);
  if (not OK(status)) {
    FATAL << "Failed to write ELF file: " << status;
  }
  return 0;
}