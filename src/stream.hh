#pragma once

#include "status.hh"
#include "vec.hh"

namespace maf {

struct Stream {
  Vec<> inbox;
  Vec<> outbox;

  virtual ~Stream() = default;

  // Flush the contents of `outbox`.
  //
  // This method should be implemented by the Stream implementations (TCP, TLS).
  virtual void Send() = 0;

  // Close the connection.
  //
  // This method should be implemented by the Stream implementations (TCP, TLS).
  virtual void Close() = 0;

  // Called after new data was added to `inbox`.
  //
  // This method should be implemented by the Stream users.
  virtual void NotifyReceived() = 0;

  // Called when the connection is closed.
  virtual void NotifyClosed() {}

  virtual operator Status &() = 0;
};

}; // namespace maf