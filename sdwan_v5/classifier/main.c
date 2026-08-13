#include "classifier.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

volatile sig_atomic_t sdwan_stop = 0;
static void stop_handler(int signal_number) { (void)signal_number; sdwan_stop = 1; }

static unsigned long number(const char *value, const char *name) {
  char *end = NULL; errno = 0; unsigned long result = strtoul(value, &end, 10);
  if (errno || !end || *end) { fprintf(stderr, "invalid %s: %s\n", name, value); exit(2); }
  return result;
}

static void usage(const char *program) {
  fprintf(stderr, "usage: %s --site NAME --queue-start N --queue-end N --policy-socket PATH --event-socket PATH [options]\n", program);
}

int main(int argc, char **argv) {
  sdwan_config config = {.queue_maxlen = 4096, .socket_buffer = 8388608,
    .path_mask = 255, .terminal_bit = 256, .provisional_bit = 512,
    .emergency_bit = 1024, .fallback_mark = 513, .tcp_budget = 32,
    .udp_budget = 20, .inspection_timeout_s = 15, .max_flows = 8192,
    .tcp_handshake_timeout_s = 30, .tcp_established_timeout_s = 900,
    .tcp_closing_timeout_s = 15, .udp_timeout_s = 120, .dns_timeout_s = 30,
    .metadata_timeout_s = 60, .max_lifetime_s = 3600,
    .overload_circuit_s = 1,
    .fail_open = true};
  static const struct option options[] = {
    {"site", required_argument, NULL, 1}, {"queue-start", required_argument, NULL, 2},
    {"queue-end", required_argument, NULL, 3}, {"queue-maxlen", required_argument, NULL, 4},
    {"socket-buffer", required_argument, NULL, 5}, {"policy-socket", required_argument, NULL, 6},
    {"event-socket", required_argument, NULL, 7}, {"path-mask", required_argument, NULL, 8},
    {"terminal-bit", required_argument, NULL, 9}, {"provisional-bit", required_argument, NULL, 10},
    {"emergency-bit", required_argument, NULL, 11}, {"fallback-mark", required_argument, NULL, 12},
    {"tcp-budget", required_argument, NULL, 13}, {"udp-budget", required_argument, NULL, 14},
    {"inspection-timeout", required_argument, NULL, 15}, {"max-flows", required_argument, NULL, 16},
    {"tcp-handshake-timeout", required_argument, NULL, 17},
    {"tcp-established-timeout", required_argument, NULL, 18},
    {"tcp-closing-timeout", required_argument, NULL, 19}, {"udp-timeout", required_argument, NULL, 20},
    {"max-lifetime", required_argument, NULL, 21}, {"fail-mode", required_argument, NULL, 22},
    {"overload-circuit", required_argument, NULL, 23},
    {"dns-timeout", required_argument, NULL, 24},
    {"metadata-timeout", required_argument, NULL, 25},
    {NULL, 0, NULL, 0}};
  int option;
  while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
    switch (option) {
      case 1: snprintf(config.site, sizeof(config.site), "%s", optarg); break;
      case 2: config.queue_start = number(optarg, "queue-start"); break;
      case 3: config.queue_end = number(optarg, "queue-end"); break;
      case 4: config.queue_maxlen = number(optarg, "queue-maxlen"); break;
      case 5: config.socket_buffer = number(optarg, "socket-buffer"); break;
      case 6: snprintf(config.policy_socket, sizeof(config.policy_socket), "%s", optarg); break;
      case 7: snprintf(config.event_socket, sizeof(config.event_socket), "%s", optarg); break;
      case 8: config.path_mask = number(optarg, "path-mask"); break;
      case 9: config.terminal_bit = number(optarg, "terminal-bit"); break;
      case 10: config.provisional_bit = number(optarg, "provisional-bit"); break;
      case 11: config.emergency_bit = number(optarg, "emergency-bit"); break;
      case 12: config.fallback_mark = number(optarg, "fallback-mark"); break;
      case 13: config.tcp_budget = number(optarg, "tcp-budget"); break;
      case 14: config.udp_budget = number(optarg, "udp-budget"); break;
      case 15: config.inspection_timeout_s = number(optarg, "inspection-timeout"); break;
      case 16: config.max_flows = number(optarg, "max-flows"); break;
      case 17: config.tcp_handshake_timeout_s = number(optarg, "tcp-handshake-timeout"); break;
      case 18: config.tcp_established_timeout_s = number(optarg, "tcp-established-timeout"); break;
      case 19: config.tcp_closing_timeout_s = number(optarg, "tcp-closing-timeout"); break;
      case 20: config.udp_timeout_s = number(optarg, "udp-timeout"); break;
      case 21: config.max_lifetime_s = number(optarg, "max-lifetime"); break;
      case 22: config.fail_open = strcmp(optarg, "open") == 0; break;
      case 23: config.overload_circuit_s = number(optarg, "overload-circuit"); break;
      case 24: config.dns_timeout_s = number(optarg, "dns-timeout"); break;
      case 25: config.metadata_timeout_s = number(optarg, "metadata-timeout"); break;
      default: usage(argv[0]); return 2;
    }
  }
  if (!config.site[0] || !config.policy_socket[0] || !config.event_socket[0] ||
      config.queue_end < config.queue_start || config.queue_end - config.queue_start > 31) {
    usage(argv[0]); return 2;
  }
  signal(SIGINT, stop_handler); signal(SIGTERM, stop_handler);
  sdwan_policy_store policy; sdwan_event_queue events;
  if (!sdwan_policy_store_init(&policy, &config) || !sdwan_event_queue_init(&events, config.event_socket)) return 1;
  size_t count = (size_t)(config.queue_end - config.queue_start + 1);
  sdwan_worker *workers = calloc(count, sizeof(*workers)); if (!workers) return 1;
  for (size_t i = 0; i < count; ++i) {
    if (!sdwan_worker_init(&workers[i], (uint16_t)(config.queue_start + i), &config, &policy, &events)) {
      fprintf(stderr, "worker initialization failed\n");
      for (size_t j = 0; j < i; ++j) sdwan_worker_destroy(&workers[j]);
      free(workers); sdwan_event_queue_destroy(&events); sdwan_policy_store_destroy(&policy); return 1;
    }
  }
  struct { sdwan_policy_store *store; sdwan_config *config; } listener = {&policy, &config};
  pthread_t policy_thread;
  if (pthread_create(&policy_thread, NULL, sdwan_policy_listener, &listener) != 0) {
    fprintf(stderr, "policy listener initialization failed\n");
    for (size_t i = 0; i < count; ++i) sdwan_worker_destroy(&workers[i]);
    free(workers); sdwan_event_queue_destroy(&events); sdwan_policy_store_destroy(&policy); return 1;
  }
  size_t started_workers = 0;
  for (; started_workers < count; ++started_workers)
    if (pthread_create(&workers[started_workers].thread, NULL, sdwan_worker_run,
                       &workers[started_workers]) != 0) {
      fprintf(stderr, "NFQUEUE thread creation failed\n"); sdwan_stop = 1; break;
    }
  for (unsigned attempt = 0; attempt < 100; ++attempt) {
    bool all_ready = true, any_failed = false;
    for (size_t i = 0; i < count; ++i) {
      all_ready = all_ready && atomic_load(&workers[i].ready);
      any_failed = any_failed || atomic_load(&workers[i].failed);
    }
    if (all_ready || any_failed) break;
    usleep(10000);
  }
  for (size_t i = 0; i < count; ++i)
    if (!atomic_load(&workers[i].ready)) {
      fprintf(stderr, "NFQUEUE worker %u did not become ready\n", workers[i].queue_number);
      sdwan_stop = 1;
    }
  while (!sdwan_stop) sleep(1);
  for (size_t i = 0; i < started_workers; ++i) pthread_join(workers[i].thread, NULL);
  pthread_join(policy_thread, NULL);
  for (size_t i = 0; i < count; ++i) sdwan_worker_destroy(&workers[i]);
  free(workers); sdwan_event_queue_destroy(&events); sdwan_policy_store_destroy(&policy); return 0;
}
