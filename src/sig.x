SECTIONS {
  .note.maf.sig.ed25519 : {
    KEEP(*(.note.maf.sig.ed25519))
  }
} INSERT BEFORE .init;