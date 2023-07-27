SECTIONS {
  .note.maf.version : {
    KEEP(*(.note.maf.version))
  }
} INSERT AFTER .note.ABI-tag;