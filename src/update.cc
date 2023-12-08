#include "update.hh"

#include <cstring>
#include <strings.h>

#include "../build/generated/version.hh"
#include "atexit.hh"
#include "ed25519.hh"
#include "elf.hh"
#include "http_client.hh"
#include "log.hh"
#include "optional.hh"
#include "path.hh"
#include "status.hh"
#include "timer.hh"
#include "virtual_fs.hh"

namespace maf::update {

Config config;
Status status;

Optional<Timer> timer;

Optional<http::Get> get;

static void ParseU32(StrView &str, U32 &out) {
  while (not str.empty() and ('0' <= str[0]) and (str[0] <= '9')) {
    out *= 10;
    out += str[0] - '0';
    str.remove_prefix(1);
  }
}

// Represents versions produced by `git describe --tags`.
// For example: "v1.33.8-99-deadbeef"
struct ParsedVersion {
  U32 major = 0;
  U32 minor = 0;
  U32 patch = 0;
  U32 extra_commits = 0;
  Str current_commit = "";

  ParsedVersion(StrView str) {
    if (str.empty() or str[0] != 'v')
      return;
    str.remove_prefix(1);
    ParseU32(str, major);
    if (str.empty() or str[0] != '.')
      return;
    str.remove_prefix(1);
    ParseU32(str, minor);
    if (str.empty() or str[0] != '.')
      return;
    str.remove_prefix(1);
    ParseU32(str, patch);
    if (str.empty() or str[0] != '-')
      return;
    str.remove_prefix(1);
    ParseU32(str, extra_commits);
    if (str.empty() or str[0] != '-')
      return;
    str.remove_prefix(1);
    current_commit = str;
  }
};

static bool IsUpdate(ParsedVersion &old_version, ParsedVersion &new_version) {
  if (old_version.major != new_version.major)
    return old_version.major < new_version.major;
  if (old_version.minor != new_version.minor)
    return old_version.minor < new_version.minor;
  if (old_version.patch != new_version.patch)
    return old_version.patch < new_version.patch;
  if (old_version.extra_commits != new_version.extra_commits)
    return old_version.extra_commits < new_version.extra_commits;
  return false;
}

static char **saved_argv;
__attribute__((constructor)) void InitUpdate(int argc, char **argv) {
  saved_argv = argv;
}

static void OnCheckFinished() {
  if (not OK(get->status)) {
    AppendErrorMessage(status) += "Couldn't download update file";
    ERROR << get->status;
    return;
  }

  // Step 1: check version

  auto version_note_span =
      elf::FindSection(get->response, ".note.maf.version", status);
  if (not OK(status)) {
    AppendErrorMessage(status) += "Update file is missing version information";
    ERROR << status;
    return;
  }

  auto &version_note = elf::Note::FromSpan(version_note_span, status);
  if (not OK(status)) {
    AppendErrorMessage(status) += "Update file version is corrupted";
    ERROR << status;
    return;
  }

  ParsedVersion my_version(kVersionNote.desc);
  auto update_version_view = StrViewOf(version_note.Desc());
  if (update_version_view.ends_with('\0')) {
    update_version_view.remove_suffix(1);
  }
  ParsedVersion update_version(update_version_view);

  if (!IsUpdate(my_version, update_version)) {
    return;
  }

  LOG << "Found update " << kVersionNote.desc << " => " << update_version_view;

  // Step 2: check signature

  auto signature_span =
      elf::FindSection(get->response, ".note.maf.sig.ed25519", status);
  if (not OK(status)) {
    AppendErrorMessage(status) += "Update file is missing signature";
    ERROR << status;
    return;
  }

  auto &signature_note = elf::Note::FromSpan(signature_span, status);
  if (not OK(status)) {
    AppendErrorMessage(status) += "Update file signature is corrupted";
    ERROR << status;
    return;
  }

  if (signature_note.Desc().size() != sizeof(ed25519::Signature)) {
    AppendErrorMessage(status) += "Update file signature has wrong size";
    ERROR << status;
    return;
  }

  // Signature was calculated for a file with the signature field zeroed out.
  // copy to stack
  ed25519::Signature signature =
      *reinterpret_cast<ed25519::Signature *>(signature_note.Desc().data());
  // zero out original signature
  bzero(signature_note.Desc().data(), signature_note.Desc().size());
  if (!signature.Verify(get->response, config.sig_key)) {
    AppendErrorMessage(status) += "Update signature failed to verify";
    ERROR << status;
    return;
  }
  // put the signature back
  memcpy(signature_note.Desc().data(), &signature, sizeof(signature));

  // Step 3: write update file

  auto my_path = Path("/proc/self/exe").ReadLink(status);
  if (not OK(status)) {
    AppendErrorMessage(status) +=
        "Update failed because couldn't read main binary path";
    ERROR << status;
    return;
  }

  Path update_path = my_path.WithStem(my_path.Stem() + ".update");

  fs::Write(fs::real, update_path, get->response, status, 0775);
  if (not OK(status)) {
    AppendErrorMessage(status) += "Update failed while writing updated file";
    ERROR << status;
    return;
  }

  update_path.Rename(my_path, status);
  if (not OK(status)) {
    AppendErrorMessage(status) += "Update failed while replacing old binary";
    ERROR << status;
    return;
  }

  ExitCleanup();

  if (execve(my_path, saved_argv, environ) < 0) {
    AppendErrorMessage(status) += "Failed to execve() updated binary";
    ERROR << status;
    return;
  }
}

static void Check() {
  LOG << "Checking for updates";
  get.emplace(config.url, OnCheckFinished);
}

void Start() {
  if ((config.first_check_delay_s != 0) or (config.check_interval_s != 0)) {
    timer.emplace();
    timer->handler = Check;
    timer->Arm(config.first_check_delay_s, config.check_interval_s);
    if (not OK(timer->status)) {
      AppendErrorMessage(status) += timer->status.ToStr();
    }
  } else {
    Check();
  }
}

void Stop() { timer.reset(); }

} // namespace maf::update