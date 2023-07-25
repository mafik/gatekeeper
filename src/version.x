SECTIONS {
  maf.version : {
    KEEP(*(maf.version))
  }
} INSERT AFTER .note.ABI-tag;