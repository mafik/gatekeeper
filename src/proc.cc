#include "proc.hh"

#include <dirent.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "fd.hh"
#include "format.hh"
#include "virtual_fs.hh"

namespace maf {

struct linux_dirent64 {
  U64 d_ino;     /* 64-bit inode number */
  U64 d_off;     /* 64-bit offset to next structure */
  U16 d_reclen;  /* Size of this linux_dirent64 */
  U8 d_type;     /* File type */
  char d_name[]; /* Filename (null-terminated) */
};

Generator<U32> ScanProcesses(Status &status) {
  FD proc(open("/proc", O_RDONLY | O_DIRECTORY));
  if (proc < 0) {
    status() += "Couldn't open /proc directory";
    co_return;
  }
  while (true) {
    U8 buf[4096];
    SSize ret = syscall(SYS_getdents64, proc.fd, buf, sizeof(buf));
    if (ret == 0) {
      co_return;
    }
    for (linux_dirent64 *ent = (linux_dirent64 *)buf;
         ent < (linux_dirent64 *)(buf + ret);
         ent = (linux_dirent64 *)((U8 *)ent + ent->d_reclen)) {
      if (ent->d_type == DT_DIR && ent->d_name[0] >= '0' &&
          ent->d_name[0] <= '9') {
        U32 pid = atoi(ent->d_name);
        co_yield pid;
      }
    }
  }
}

Generator<std::pair<U32, StrView>> ScanOpenedFiles(U32 pid, Status &status) {
  Str dir = f("/proc/%d/fd", pid);
  FD proc(open(dir.c_str(), O_RDONLY | O_DIRECTORY));
  if (proc < 0) {
    if (errno == ENOENT) {
      // Process was closed. Ignore it.
      errno = 0;
    } else {
      status() += "Couldn't open " + dir + " directory";
    }
    co_return;
  }
  while (true) {
    U8 buf[4096];
    SSize ret = syscall(SYS_getdents64, proc.fd, buf, sizeof(buf));
    if (ret == 0) {
      co_return;
    }
    for (linux_dirent64 *ent = (linux_dirent64 *)buf;
         ent < (linux_dirent64 *)(buf + ret);
         ent = (linux_dirent64 *)((U8 *)ent + ent->d_reclen)) {
      if (ent->d_name[0] == '.') {
        continue;
      }
      char link[PATH_MAX + 1];
      SSize readlink_ret = readlinkat(proc.fd, ent->d_name, link, sizeof(link));
      if (readlink_ret == -1) {
        if (errno == ENOENT) {
          // The file was deleted. Ignore it.
          errno = 0;
          continue;
        }
        status() += "Couldn't read link at " + dir + "/" + ent->d_name;
        co_return;
      }
      co_yield std::make_pair(atoi(ent->d_name), StrView(link, readlink_ret));
    }
  }
}

Str GetProcessName(U32 pid, Status &status) {
  Path path = f("/proc/%d/comm", pid);
  Str process_name = fs::Read(fs::real, path, status);
  if (!OK(status)) {
    return "";
  }
  if (process_name.ends_with('\n')) {
    process_name.pop_back();
  }
  return process_name;
}

} // namespace maf