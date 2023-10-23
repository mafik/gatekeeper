#pragma once

#include "ed25519.hh"
#include "fn.hh"
#include "status.hh"
#include "str.hh"

// Includes functions & data related to the auto-update mechanism.
//
// All data is kept as globals & functions (rather than structs & methods)
// because auto-update mechanism is expected to be a global per-application
// thing.
//
// This module assumes a single-binary application, without any external files.
//
// The I/O relies on the `epoll` module so make sure to call `epoll::Init()` at
// app startup & `epoll::Loop()` in order for the work to be done.
namespace maf::update {

struct Config {
  Str url;

  // Defaults to https://github.com/mafik.keys
  ed25519::Public sig_key = {.bytes = {0x31, 0x1b, 0xd1, 0xa7, 0x7f, 0x0c, 0x4e,
                                       0x40, 0xa8, 0x10, 0xfd, 0xc6, 0xeb, 0xc2,
                                       0x39, 0xb0, 0xe7, 0xcb, 0x67, 0x62, 0x37,
                                       0xd7, 0xdf, 0x2b, 0x3c, 0x5e, 0x83, 0xfa,
                                       0x91, 0x24, 0x1b, 0x48}};

  double first_check_delay_s;

  // Value of 0 means "don't check periodically".
  double check_interval_s;

  // Called right before the process is replaced with the new version.
  //
  // This is a good place to save any state that needs to be restored later.
  Fn<void()> PreUpdate;
};

extern Config config;
extern Status status;

void Start();
void Stop();

} // namespace maf::update