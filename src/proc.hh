#pragma once

// Functions for working with the /proc filesystem.

#include "directory_scanner.hh"
#include "generator.hh"
#include "int.hh"
#include "status.hh"

namespace maf {

struct ProcessScanner {
  U32 pid;
  DirectoryScanner dir_scanner;

  ProcessScanner(Status &status);

  struct EndIterator {};

  struct Iterator {
    ProcessScanner &scanner;

    Iterator(ProcessScanner &scanner);
    bool operator!=(EndIterator) const;
    Iterator &operator++();
    U32 operator*() const;
  };

  Iterator begin();
  EndIterator end();
};

// Return a sequence of opened (fd, path) pairs for the given process.
Generator<std::pair<U32, StrView>> ScanOpenedFiles(U32 pid, Status &);

// Return a sequence of socket inodes for the given process.
Generator<U32> ScanOpenedSockets(U32 pid, Status &);

// Returns the name of the process with the given pid or "" in case of error.
Str GetProcessName(U32 pid, Status &);

} // namespace maf
