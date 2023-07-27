#pragma once

#include "ed25519.hh"

namespace maf {

struct SignatureNote {
  int namesz = 4;
  int descsz = sizeof(ed25519::Signature);
  int type = 3;
  char name[4] = "MAF";
  ed25519::Signature desc = {};
};

extern const SignatureNote kSignatureNote;

} // namespace maf