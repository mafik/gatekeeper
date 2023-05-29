#pragma once

#include "time.h"
#include <memory>
#include <source_location>
#include <string_view>

// Functions for logging human-readable messages.
//
// Usage:
//
//   LOG << "regular message";
//   ERROR << "error message";
//   FATAL << "stop the execution / print stack trace";
//
// Logging can also accept other types - integers & floats.
//
// In this case a short client identifier (IP address + 4-digit hash) will be
// printed before the massage. Each client will also get a random color to make
// identification easier.
//
// When executed within Emscripten, logging causes the messages to appear in the
// JavaScript console - as regular (black) messages (LOG), yellow warnings
// (ERROR) & red errors (FATAL).
//
// Logged messages can have multiple lines - the extra lines are not indented or
// treated in any special way.
//
// There is no need to add a new line character at the end of the logged message
// - it's added there automatically.

enum LogLevel {
  LOG_LEVEL_IGNORE,
  LOG_LEVEL_INFO,
  LOG_LEVEL_ERROR,
  LOG_LEVEL_FATAL
};

// Appends the logged message when destroyed.
struct Logger {
  LogLevel log_level;
  std::source_location location;
  mutable std::string buffer;

  Logger(LogLevel,
         const std::source_location location = std::source_location::current());
  ~Logger();
};

#define LOG Logger(LOG_LEVEL_INFO, std::source_location::current())
#define ERROR Logger(LOG_LEVEL_ERROR, std::source_location::current())
#define FATAL Logger(LOG_LEVEL_FATAL, std::source_location::current())

const Logger &operator<<(const Logger &, int);
const Logger &operator<<(const Logger &, unsigned);
const Logger &operator<<(const Logger &, unsigned long);
const Logger &operator<<(const Logger &, unsigned long long);
const Logger &operator<<(const Logger &, float);
const Logger &operator<<(const Logger &, double);
const Logger &operator<<(const Logger &, std::string_view);
const Logger &operator<<(const Logger &, const unsigned char *);

template <typename T>
concept loggable = requires(T &v) {
  { v.LoggableString() } -> std::convertible_to<std::string_view>;
};

const Logger &operator<<(const Logger &logger, loggable auto &t) {
  return logger << t.LoggableString();
}

void LOG_Indent(int n = 2);

void LOG_Unindent(int n = 2);

#define EVERY_N_SEC(n)                                                         \
  static time::point last_log_time;                                            \
  if (time::now() - last_log_time > time::duration(n)                          \
          ? (last_log_time = time::now(), true)                                \
          : false)
