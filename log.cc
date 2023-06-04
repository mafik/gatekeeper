#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <utility>

#include "format.hh"
#include "log.hh"
#include "math.h"
#include "term.hh"

std::vector<Logger> loggers;

static int indent = 0;

void LOG_Indent(int n) { indent += n; }

void LOG_Unindent(int n) { indent -= n; }

LogEntry::LogEntry(LogLevel log_level, const std::source_location location)
    : log_level(log_level), timestamp(std::chrono::system_clock::now()),
      location(location), buffer(), errsv(errno) {
  for (int i = 0; i < indent; ++i) {
    buffer += " ";
  }
}

LogEntry::~LogEntry() {
  if (log_level == LogLevel::Ignore) {
    return;
  }

  if (log_level == LogLevel::Fatal) {
    buffer += f(" Crashing in %s:%d [%s].", location.file_name(), location.line(),
                location.function_name());
  }

  for (auto &logger : loggers) {
    logger(*this);
  }

  if (log_level == LogLevel::Fatal) {
    abort();
  }
}

void __attribute__((__constructor__)) InitDefaultLoggers() {
  loggers.emplace_back([](const LogEntry &e) {
#if defined(__EMSCRIPTEN__)
    if (e.log_level == LogLevel::Error) {
      EM_ASM({ console.warn(UTF8ToString($0)); }, e.buffer.c_str());
    } else if (e.log_level == LogLevel::Fatal) {
      EM_ASM({ console.error(UTF8ToString($0)); }, e.buffer.c_str());
    } else {
      EM_ASM({ console.log(UTF8ToString($0)); }, e.buffer.c_str());
    }
#else
    printf("%s\n", e.buffer.c_str());
#endif
  });
}

const LogEntry &operator<<(const LogEntry &logger, int i) {
  logger.buffer += std::to_string(i);
  return logger;
}

const LogEntry &operator<<(const LogEntry &logger, unsigned i) {
  logger.buffer += std::to_string(i);
  return logger;
}

const LogEntry &operator<<(const LogEntry &logger, unsigned long i) {
  logger.buffer += std::to_string(i);
  return logger;
}

const LogEntry &operator<<(const LogEntry &logger, unsigned long long i) {
  logger.buffer += std::to_string(i);
  return logger;
}

const LogEntry &operator<<(const LogEntry &logger, float f) {
  logger.buffer += std::to_string(f);
  return logger;
}

const LogEntry &operator<<(const LogEntry &logger, double d) {
  logger.buffer += std::to_string(d);
  return logger;
}

const LogEntry &operator<<(const LogEntry &logger, std::string_view s) {
  logger.buffer += s;
  return logger;
}

const LogEntry &operator<<(const LogEntry &logger, const unsigned char *s) {
  logger.buffer += (const char *)s;
  return logger;
}

const LogEntry &operator<<(const LogEntry &logger, Status &status) {
  logger.buffer += status.ToString();
  logger.errsv = status.errsv;
  return logger;
}