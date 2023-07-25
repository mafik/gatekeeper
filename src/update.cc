#include "update.hh"

#include "http_client.hh"
#include "log.hh"
#include "status.hh"
#include "timer.hh"

namespace maf::update {

Config config;
Status status;

Optional<Timer> timer;

Optional<http::Get> get;

static void OnGetFinished() {
  LOG << "OnGetFinished. Result: " << get->response;
  LOG << "data_begin: " << get->data_begin;
}

static void Check() { get.emplace(config.url, OnGetFinished); }

void Start() {
  if ((config.first_check_delay_s != 0) or (config.check_interval_s != 0)) {
    timer.emplace();
    timer->handler = Check;
    timer->Arm(config.first_check_delay_s, config.check_interval_s);
    if (not OK(timer->status)) {
      AppendErrorMessage(status) += timer->status.ToString();
    }
  } else {
    Check();
  }
}

void Stop() { timer.reset(); }

} // namespace maf::update