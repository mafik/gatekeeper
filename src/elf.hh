#pragma once

// Functions for working with ELF files

#include "span.hh"
#include "status.hh"
#include "str.hh"

namespace maf::elf {

struct Note {
  U32 namesz;
  U32 descsz;
  U32 type;
  static Note &FromSpan(Span<> span, Status &status);
  StrView Name();
  Span<> Desc();
};

// Find a section in an ELF file by name.
//
// This function should be safe against maliciously crafted ELF files.
Span<> FindSection(Span<> elf_contents, StrView section_name, Status &status);

} // namespace maf::elf