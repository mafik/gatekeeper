#pragma once

// Functions for working with ELF files

#include "span.hh"
#include "status.hh"
#include "str.hh"

namespace maf::elf {

// Find a section in an ELF file by name.
//
// This function should be safe against maliciously crafted ELF files.
Span<> FindSection(Span<> elf_contents, StrView section_name, Status &status);

} // namespace maf::elf