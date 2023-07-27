#include "elf.hh"

#include <limits>

#include "int.hh"
#include "status.hh"

namespace maf::elf {

struct Elf64 {
  using Addr = U32;
  struct SectionHeader {
    U32 name;      /* Section name (string tbl index) */
    U32 type;      /* Section type */
    U64 flags;     /* Section flags */
    U64 addr;      /* Section virtual addr at execution */
    U64 offset;    /* Section file offset */
    U64 size;      /* Section size in bytes */
    U32 link;      /* Link to another section */
    U32 info;      /* Additional section information */
    U64 addralign; /* Section alignment */
    U64 entsize;   /* Entry size if section holds table */
  };
  struct Header {
    char ident[16]; /* Magic number and other info */
    U16 type;       /* Object file type */
    U16 machine;    /* Architecture */
    U32 version;    /* Object file version */
    U64 entry;      /* Entry point virtual address */
    U64 phoff;      /* Program header table file offset */
    U64 shoff;      /* Section header table file offset */
    U32 flags;      /* Processor-specific flags */
    U16 ehsize;     /* ELF header size in bytes */
    U16 phentsize;  /* Program header table entry size */
    U16 phnum;      /* Program header table entry count */
    U16 shentsize;  /* Section header table entry size */
    U16 shnum;      /* Section header table entry count */
    U16 shstrndx;   /* Section header string table index */
  };
};

struct Elf32 {
  using Addr = U32;
  struct SectionHeader {
    U32 name;      /* Section name (string tbl index) */
    U32 type;      /* Section type */
    U32 flags;     /* Section flags */
    U32 addr;      /* Section virtual addr at execution */
    U32 offset;    /* Section file offset */
    U32 size;      /* Section size in bytes */
    U32 link;      /* Link to another section */
    U32 info;      /* Additional section information */
    U32 addralign; /* Section alignment */
    U32 entsize;   /* Entry size if section holds table */
  };

  struct Header {
    char ident[16]; /* Magic number and other info */
    U16 type;       /* Object file type */
    U16 machine;    /* Architecture */
    U32 version;    /* Object file version */
    U32 entry;      /* Entry point virtual address */
    U32 phoff;      /* Program header table file offset */
    U32 shoff;      /* Section header table file offset */
    U32 flags;      /* Processor-specific flags */
    U16 ehsize;     /* ELF header size in bytes */
    U16 phentsize;  /* Program header table entry size */
    U16 phnum;      /* Program header table entry count */
    U16 shentsize;  /* Section header table entry size */
    U16 shnum;      /* Section header table entry count */
    U16 shstrndx;   /* Section header string table index */
  };
};

template <typename T> T SafeAdd(T a, T b) {
  if (a > std::numeric_limits<T>::max() - b) {
    return std::numeric_limits<T>::max();
  }
  return a + b;
}

template <typename Elf>
static Span<> FindSection(Span<> elf_contents, StrView section_name,
                          Status &status) {
  using Header = typename Elf::Header;
  using SectionHeader = typename Elf::SectionHeader;
  using Addr = typename Elf::Addr;
  if (elf_contents.size() < sizeof(Header)) {
    AppendErrorMessage(status) += "File too small to contain an ELF header";
    return {};
  }
  Header &header = *reinterpret_cast<Header *>(elf_contents.data());
  Size string_table_header_offset =
      SafeAdd<Addr>(header.shoff, header.shstrndx * sizeof(SectionHeader));
  if (SafeAdd<Addr>(string_table_header_offset, sizeof(SectionHeader)) >
      elf_contents.size()) {
    AppendErrorMessage(status) += "ELF section name table header out of bounds";
    return {};
  }
  SectionHeader &shstrtab = *reinterpret_cast<SectionHeader *>(
      elf_contents.data() + string_table_header_offset);
  if (SafeAdd<Addr>(shstrtab.offset, shstrtab.size) > elf_contents.size()) {
    AppendErrorMessage(status) += "ELF section name table out of bounds";
    return {};
  }
  if (elf_contents[std::max<Addr>(1, shstrtab.offset + shstrtab.size) - 1] !=
      '\0') {
    AppendErrorMessage(status) += "ELF section name table not null-terminated";
    return {};
  }
  char *string_table = elf_contents.data() + shstrtab.offset;
  if (SafeAdd<Addr>(header.shoff, header.shnum * sizeof(SectionHeader)) >
      elf_contents.size()) {
    AppendErrorMessage(status) += "ELF section headers out of bounds";
    return {};
  }
  for (int section_i = 0; section_i < header.shnum; ++section_i) {
    SectionHeader &section_header = *reinterpret_cast<SectionHeader *>(
        elf_contents.data() + header.shoff + section_i * sizeof(SectionHeader));
    if (section_header.name >= shstrtab.size) {
      AppendErrorMessage(status) += "ELF section name out of bounds";
      return {};
    }
    StrView current_section_name = string_table + section_header.name;
    if (current_section_name == section_name) {
      return Span<>(elf_contents.data() + section_header.offset,
                    section_header.size);
    }
  }
  AppendErrorMessage(status) += "Section not found: " + Str(section_name);
  return {};
}

Span<> FindSection(Span<> elf_contents, StrView section_name, Status &status) {
  if (elf_contents.size() < 5) {
    AppendErrorMessage(status) += "ELF file too small";
    return {};
  }
  if (elf_contents[4] == 1) {
    return FindSection<Elf32>(elf_contents, section_name, status);
  } else if (elf_contents[4] == 2) {
    return FindSection<Elf64>(elf_contents, section_name, status);
  } else {
    AppendErrorMessage(status) += "Invalid ELF class";
    return {};
  }
}

} // namespace maf::elf