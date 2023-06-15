#pragma once

#include <cstdint>
#include <string>

#include "fd.hh"

// C++ wrappers around the Linux epoll facility.
namespace epoll {

// Base class for objects that would like to receive epoll updates.
struct Listener {
  // File descriptor monitored by this Listener.
  FD fd;

  // Whether this Listener is interested in reading data from its file
  // descriptor. Default implementation assumes that derived classses are always
  // interested in new data.
  virtual bool ListenReadAvailability();

  // Whether this Listener is interested in writing data into its file
  // descriptor. Default implementation assumes that derived classses are not
  // interested in outputting any data.
  virtual bool ListenWriteAvailability();
  
  // Method called whenever a registered file descriptor becomes ready for reading.
  virtual void NotifyRead(std::string &error) = 0;
  
  // Method called whenever a registered file descriptor becomes ready for writing.
  virtual void NotifyWrite(std::string &error) {};

  virtual const char* Name() const = 0;
};

// File descriptor of the epoll instance.
extern int fd;

// Number of active Listeners.
extern int listener_count;

void Init();

// Add a new listener to this epoll instance.
void Add(Listener *, std::string &error);

// Change the listening flags of this listener. This can be called whenever a
// Listener becomes (or stops being) interested in some type of update.
void Mod(Listener *, std::string &error);

// Remove the specified file descriptor from this epoll instance.
void Del(Listener *, std::string &error);

// Poll events until an error is returned or all listeners drop.
void Loop(std::string &error);

} // namespace epoll
