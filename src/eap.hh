#pragma once

#include "status.hh"

// Helpers for working with 802.1X (EAP).
namespace maf::eap {

struct KeyInformation {
  bool key_mic : 1;
  bool secure : 1;
  bool error : 1;
  bool request : 1;
  bool encrypted_key_data : 1;
  bool smk_message : 1;
  int reserved : 2;
  int key_descriptor_version : 3;
  bool key_type_pairwise : 1;
  int key_index : 2;
  bool install : 1;
  bool key_ack : 1;

  void Validate(KeyInformation expected, Status &status) const;
} __attribute__((packed));

static_assert(sizeof(KeyInformation) == 2, "KeyInformation must be 2 bytes");

} // namespace maf::eap