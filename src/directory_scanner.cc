#include "directory_scanner.hh"

#include <fcntl.h>

namespace maf {

static void ReadMoreDents(DirectoryScanner &scanner) {
  SSize ret = syscall(SYS_getdents64, scanner.dir.fd, scanner.buf.data(),
                      scanner.buf.size());
  if (ret == 0) {
    scanner.dir.Close();
    return;
  }
  scanner.dents = Span<U8>(scanner.buf.data(), ret);
}

DirectoryScanner::DirectoryScanner(const char *dir_path, Status &status)
    : dents(), dir(open(dir_path, O_RDONLY | O_DIRECTORY)) {
  if (dir < 0) {
    AppendErrorMessage(status) +=
        "Couldn't open " + Str(dir_path) + " directory";
    return;
  }
  ReadMoreDents(*this);
}

DirectoryScanner::Iterator::Iterator(DirectoryScanner &scanner)
    : scanner(scanner) {}

bool DirectoryScanner::Iterator::operator!=(EndIterator) const {
  return scanner.dir.Opened();
}

DirectoryScanner::Iterator &DirectoryScanner::Iterator::operator++() {
  // Assuming that Linux doesn't return truncated dents.
  linux_dirent64 &ent = scanner.dents.As<linux_dirent64>();
  scanner.dents.RemovePrefix(ent.d_reclen);
  if (scanner.dents.Empty()) {
    ReadMoreDents(scanner);
  }
  return *this;
}

linux_dirent64 &DirectoryScanner::Iterator::operator*() const {
  return scanner.dents.As<linux_dirent64>();
}

DirectoryScanner::Iterator DirectoryScanner::begin() { return Iterator(*this); }

DirectoryScanner::EndIterator DirectoryScanner::end() { return {}; }

} // namespace maf