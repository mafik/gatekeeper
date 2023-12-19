#include "expirable.hh"
#include "atexit.hh"

#include <cmath>
#include <set>

using namespace std;

namespace maf {

struct OrderByExpiration {
  using is_transparent = true_type;
  bool operator()(const Expirable *a, const Expirable *b) const {
    return a->expiration < b->expiration;
  }
  bool operator()(const Expirable *a,
                  chrono::steady_clock::time_point b) const {
    return a->expiration < b;
  }
  bool operator()(chrono::steady_clock::time_point a,
                  const Expirable *b) const {
    return a < b->expiration;
  }
};

static thread_local multiset<Expirable *, OrderByExpiration> expiration_queue;

Expirable::Expirable() : expiration(nullopt) {}

Expirable::Expirable(chrono::steady_clock::time_point expiration)
    : expiration(expiration) {
  AddToExpirationQueue();
}

Expirable::Expirable(chrono::steady_clock::duration ttl)
    : Expirable(chrono::steady_clock::now() + ttl) {}

Expirable::~Expirable() { RemoveFromExpirationQueue(); }

void Expirable::AddToExpirationQueue() {
  if (expiration == nullopt) {
    return;
  }
  expiration_queue.insert(this);
}

void Expirable::RemoveFromExpirationQueue() const {
  if (expiration == nullopt) {
    return;
  }
  auto [begin, end] = expiration_queue.equal_range(*expiration);
  for (auto it = begin; it != end; ++it) {
    if (*it == this) {
      expiration_queue.erase(it);
      break;
    }
  }
}

void Expirable::UpdateExpiration(
    chrono::steady_clock::time_point new_expiration) {
  RemoveFromExpirationQueue();
  expiration = new_expiration;
  expiration_queue.insert(this);
}

void Expirable::UpdateExpiration(std::chrono::steady_clock::duration ttl) {
  UpdateExpiration(chrono::steady_clock::now() + ttl);
}

void Expirable::Expire() {
  auto now = chrono::steady_clock::now();
  while (!expiration_queue.empty() &&
         (*expiration_queue.begin())->expiration < now) {
    delete *expiration_queue.begin();
  }
}

void Expirable::Init() {
  AtExit([]() {
    while (!expiration_queue.empty()) {
      delete *expiration_queue.begin();
    }
  });
}

} // namespace maf