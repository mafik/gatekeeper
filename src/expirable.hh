#pragma once

#include <chrono>

#include "optional.hh"

namespace maf {

// Mixin class that can be used to automatically delete objects after a certain
// expiration time.
//
// Expirable objects can be refreshed by calling `UpdateExpiration`.
//
// Expirable objects are deleted by the `Expire` function, which should be
// called periodically.
struct Expirable {
  // Don't modify directly. Use `UpdateExpiration` instead.
  Optional<std::chrono::steady_clock::time_point> expiration;

  // Initialize without inserting into expiration queue.
  Expirable();

  // Initialize and insert into expiration queue with the given expiration.
  Expirable(std::chrono::steady_clock::time_point expiration);

  // Initialize and insert into expiration queue with the given TTL.
  Expirable(std::chrono::steady_clock::duration ttl);

  // Destructor automatically removes `this` from the expiration queue.
  virtual ~Expirable();

  // O(log n)
  void UpdateExpiration(std::chrono::steady_clock::time_point new_expiration);
  void UpdateExpiration(std::chrono::steady_clock::duration ttl);

  // O(1)
  static void Expire();

private:
  void AddToExpirationQueue();
  void RemoveFromExpirationQueue() const;
};

} // namespace maf