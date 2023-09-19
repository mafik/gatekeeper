SECTIONS {
  .note.maf.version : {
    KEEP(*(.note.maf.version))
  }
} INSERT BEFORE .init;