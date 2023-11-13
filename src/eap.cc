#include "eap.hh"

namespace maf::eap {

void KeyInformation::Validate(KeyInformation expected, Status &status) const {

  if (key_descriptor_version != expected.key_descriptor_version) {
    AppendErrorMessage(status) += "Unknown key descriptor version " +
                                  std::to_string(key_descriptor_version);
  }
  if (key_type_pairwise != expected.key_type_pairwise) {
    AppendErrorMessage(status) +=
        "Key Type not set to " + std::to_string(key_type_pairwise);
  }
  if (key_index != expected.key_index) {
    AppendErrorMessage(status) +=
        "Key Index set to " + std::to_string(key_index);
  }
  if (key_ack != expected.key_ack) {
    AppendErrorMessage(status) +=
        expected.key_ack ? "Key ACK not set" : "Key ACK set";
  }
  if (key_mic != expected.key_mic) {
    AppendErrorMessage(status) +=
        expected.key_mic ? "Key MIC not set" : "Key MIC set";
  }
  if (secure != expected.secure) {
    AppendErrorMessage(status) +=
        expected.secure ? "Secure bit not set" : "Secure bit set";
  }
  if (error != expected.error) {
    AppendErrorMessage(status) +=
        expected.error ? "Error bit not set" : "Error bit set";
  }
  if (request != expected.request) {
    AppendErrorMessage(status) +=
        expected.request ? "Request bit not set" : "Request bit set";
  }
  if (encrypted_key_data != expected.encrypted_key_data) {
    AppendErrorMessage(status) += expected.encrypted_key_data
                                      ? "Encrypted Key Data bit not set"
                                      : "Encrypted Key Data bit set";
  }
  if (smk_message != expected.smk_message) {
    AppendErrorMessage(status) += expected.smk_message
                                      ? "SMK Message bit not set"
                                      : "SMK Message bit set";
  }
  if (!OK(status)) {
    AppendErrorMessage(status) += "Invalid Key Information flags";
  }
}

} // namespace maf::eap