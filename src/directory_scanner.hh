#pragma once

#include "arr.hh"
#include "fd.hh"
#include "int.hh"
#include "span.hh"

namespace maf {

struct linux_dirent64 {
  U64 d_ino;     /* 64-bit inode number */
  U64 d_off;     /* 64-bit offset to next structure */
  U16 d_reclen;  /* Size of this linux_dirent64 */
  U8 d_type;     /* File type */
  char d_name[]; /* Filename (null-terminated) */
};

struct DirectoryScanner {
  Span<U8> dents;
  FD dir;
  Arr<U8, 4096> buf;

  DirectoryScanner(const char *dir_path, Status &status);

  struct EndIterator {};

  struct Iterator {
    DirectoryScanner &scanner;

    Iterator(DirectoryScanner &scanner);
    bool operator!=(EndIterator) const;
    Iterator &operator++();
    linux_dirent64 &operator*() const;
  };

  Iterator begin();
  EndIterator end();
};

} // namespace maf