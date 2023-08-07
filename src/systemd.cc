#include "systemd.hh"

#include <cerrno>
#include <optional>
#include <sys/stat.h>
#include <sys/un.h>

#include "format.hh"
#include "log.hh"
#include "status.hh"
#include "timer.hh"
#include "virtual_fs.hh"

using namespace maf;

namespace systemd {

std::optional<FD> notify_socket;
std::optional<FD> journal_socket;

static void Notify(StrView msg) {
  if (notify_socket) {
    send(*notify_socket, msg.data(), msg.size(), MSG_NOSIGNAL);
  }
}

static void LogErrorAsStatus(const LogEntry &log_entry) {
  if (log_entry.log_level >= LogLevel::Error) {
    Str status =
        f("STATUS=%s\nERRNO=%i", log_entry.buffer.c_str(), log_entry.errsv);
    Notify(status.c_str());
  }
}

static void StructuredLog(const LogEntry &log_entry) {
  Str message = "SYSLOG_IDENTIFIER=gatekeeper\nMESSAGE";
  if (log_entry.buffer.contains('\n')) {
    U64 size = log_entry.buffer.size();
    message += '\n';
    message += StrView((char *)&size, sizeof(size));
    message += log_entry.buffer;
  } else {
    message += '=';
    message += log_entry.buffer;
  }
  message += '\n';
  message += "PRIORITY=";
  switch (log_entry.log_level) {
  case LogLevel::Ignore:
    message += "7";
    break;
  case LogLevel::Info:
    message += "6";
    break;
  case LogLevel::Error:
    message += "3";
    break;
  case LogLevel::Fatal:
    message += "0";
    break;
  }
  message += '\n';
  message += "CODE_FILE=";
  message += log_entry.location.file_name();
  message += '\n';
  message += "CODE_LINE=";
  message += std::to_string(log_entry.location.line());
  message += '\n';
  message += "CODE_FUNC=";
  message += log_entry.location.function_name();
  message += '\n';
  if (log_entry.errsv) {
    message += "ERRNO=";
    message += std::to_string(log_entry.errsv);
    message += '\n';
  }
  send(*journal_socket, message.data(), message.size(), MSG_NOSIGNAL);
}

// See: https://systemd.io/JOURNAL_NATIVE_PROTOCOL/
static void ConfigureLogging() {
  if (char *journal_stream = getenv("JOURNAL_STREAM")) {
    int device, inode;
    if (sscanf(journal_stream, "%i:%i", &device, &inode) != 2) {
      ERROR << "Failed to parse JOURNAL_STREAM: " << journal_stream << ".";
    } else {
      struct stat stdout_stat = {};
      if (fstat(STDOUT_FILENO, &stdout_stat) != 0) {
        ERROR << "Failed to stat stdout.";
      } else if (stdout_stat.st_dev == device && stdout_stat.st_ino == inode) {
        journal_socket.emplace(socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0));
        struct sockaddr_un saddr = {
            .sun_family = AF_UNIX,
            .sun_path = "/run/systemd/journal/socket",
        };
        if (connect(*journal_socket, (struct sockaddr *)&saddr,
                    sizeof(saddr)) != 0) {
          ERROR << "Failed to connect to system journal.";
          journal_socket.reset();
          return;
        }
        loggers.clear();
        loggers.push_back(StructuredLog);
      } else {
        // STDOUT is not connected to the journal.
      }
    }
  }
}

std::optional<Timer> watchdog_timer;

// If the process is running under systemd with watchdog enabled, this function
// will periodically send watchdog pings.
//
// This function requires `epoll::Loop` to send the pings.
void StartWatchdog() {
  if (char *watchdog_pid_env = getenv("WATCHDOG_PID")) {
    int watchdog_pid = atoi(watchdog_pid_env);
    // Only send watchdog pings if this process is the watched.
    if (watchdog_pid != getpid()) {
      return;
    }
  }
  if (char *watchdog_usec_env = getenv("WATCHDOG_USEC")) {
    U64 usec = strtoull(watchdog_usec_env, nullptr, 10);
    double interval_s = usec / 2.0 / 1000000.0;
    watchdog_timer.emplace();
    watchdog_timer->handler = []() { Notify("WATCHDOG=1"); };
    watchdog_timer->Arm(interval_s, interval_s);
  }
}

// Stop the watchdog pings started by `StartWatchdog()`.
void StopWatchdog() { watchdog_timer.reset(); }

void Init() {
  if (char *notify_socket_env = getenv("NOTIFY_SOCKET")) {
    notify_socket.emplace(socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    struct sockaddr_un saddr = {
        .sun_family = AF_UNIX,
    };
    strncpy(saddr.sun_path, notify_socket_env, sizeof(saddr.sun_path) - 1);
    if (connect(*notify_socket, (struct sockaddr *)&saddr, sizeof(saddr)) !=
        0) {
      ERROR << "Failed to connect to systemd NOTIFY_SOCKET: "
            << notify_socket_env << ".";
      notify_socket.reset();
      return;
    }
    ConfigureLogging();
    loggers.push_back(LogErrorAsStatus);
    StartWatchdog();
  }
}

void OverrideEnvironment(StrView unit, StrView env, StrView value,
                         Status &status) {
  Str path = f("/etc/systemd/system/%*s.service.d", unit.size(), unit.data());
  if (mkdir(path.c_str(), 0755) < 0) {
    if (errno != EEXIST) {
      AppendErrorMessage(status) += "Failed to create directory " + path;
      return;
    }
    errno = 0;
  }
  path += "/override.conf";
  Status read_status;
  Str override_conf = "";
  ReadRealFile(
      path,
      [&](StrView old_override_conf) { override_conf = old_override_conf; },
      read_status);
  Str service_tag = "\n[Service]\n";
  Size service_tag_pos = override_conf.find(service_tag);
  if (service_tag_pos == Str::npos) {
    service_tag_pos = override_conf.size();
    override_conf += "\n[Service]\n";
  }
  Size service_begin = service_tag_pos + service_tag.size();
  Str needle = f("\nEnvironment=\"%*s=", env.size(), env.data());
  Size needle_pos = override_conf.find(needle, service_begin);
  if (needle_pos == Str::npos) {
    override_conf.insert(service_begin,
                         f("Environment=\"%*s=%*s\"\n", env.size(), env.data(),
                           value.size(), value.data()));
  } else {
    Size needle_end = override_conf.find("\"\n", needle_pos + needle.size());
    if (needle_end == Str::npos) {
      needle_end = override_conf.size();
    } else {
      needle_end += 2;
    }
    override_conf.replace(needle_pos, needle_end - needle_pos,
                          f("\nEnvironment=\"%*s=%*s\"\n", env.size(),
                            env.data(), value.size(), value.data()));
  }
  WriteFile(path, override_conf, status);
}

void Ready() { Notify("READY=1"); }

void Stop() { StopWatchdog(); }

} // namespace systemd