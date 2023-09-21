#include "proc.hh"

#include <dirent.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <unistd.h>

#include "fd.hh"
#include "format.hh"

namespace maf {

struct linux_dirent64 {
  ino64_t d_ino;           /* 64-bit inode number */
  off64_t d_off;           /* 64-bit offset to next structure */
  unsigned short d_reclen; /* Size of this dirent */
  unsigned char d_type;    /* File type */
  char d_name[];           /* Filename (null-terminated) */
};

void ScanProcesses(Fn<void(U32 pid, Status &)> callback, Status &status) {
  FD proc(open("/proc", O_RDONLY | O_DIRECTORY));
  if (proc < 0) {
    status() += "Couldn't open /proc directory";
    return;
  }
  while (true) {
    U8 buf[4096];
    SSize ret = getdents64(proc.fd, buf, sizeof(buf));
    if (ret == 0) {
      return;
    }
    for (linux_dirent64 *ent = (linux_dirent64 *)buf;
         ent < (linux_dirent64 *)(buf + ret);
         ent = (linux_dirent64 *)((U8 *)ent + ent->d_reclen)) {
      if (ent->d_type == DT_DIR && ent->d_name[0] >= '0' &&
          ent->d_name[0] <= '9') {
        U32 pid = atoi(ent->d_name);
        callback(pid, status);
        if (!OK(status)) {
          status() += "Error while scanning /proc directiories";
          return;
        }
      }
    }
  }
}

void ScanOpenedFiles(U32 pid, Fn<void(U32 fd, StrView path, Status &)> callback,
                     Status &status) {
  Str dir = f("/proc/%d/fd", pid);
  FD proc(open(dir.c_str(), O_RDONLY | O_DIRECTORY));
  if (proc < 0) {
    status() += "Couldn't open " + dir + " directory";
    return;
  }
  while (true) {
    U8 buf[4096];
    SSize ret = getdents64(proc.fd, buf, sizeof(buf));
    if (ret == 0) {
      return;
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
        status() += "Couldn't read link at " + dir + "/" + ent->d_name;
        return;
      }
      callback(atoi(ent->d_name), StrView(link, readlink_ret), status);
      if (!OK(status)) {
        status() +=
            "Error while scanning files opened by PID " + std::to_string(pid);
        return;
      }
    }
  }
}

} // namespace maf