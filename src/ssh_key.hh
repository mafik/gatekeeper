// Utilities for working with SSH keys.

#pragma once

#include "ed25519.hh"
#include "path.hh"
#include "status.hh"

namespace maf {

struct SSHKey {
  static SSHKey FromFile(const Path &, Status &);

  ed25519::Private private_key;
  ed25519::Public public_key;
  Str comment;
};

} // namespace maf