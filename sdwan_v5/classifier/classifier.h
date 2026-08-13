#ifndef SDWAN_V4_CLASSIFIER_H
#define SDWAN_V4_CLASSIFIER_H

#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include <ndpi_api.h>

#define SDWAN_MAX_PATHS 8
#define SDWAN_MAX_CLASSES 32
#define SDWAN_MAX_APPS 256
#define SDWAN_MAX_CATEGORIES 128
#define SDWAN_EVENT_CAPACITY 1024
#define SDWAN_NAME_LEN 64

typedef enum {
  SDWAN_INSPECTING = 0,
  SDWAN_PARTIAL,
  SDWAN_CLASSIFIED,
  SDWAN_TERMINAL_UNKNOWN,
  SDWAN_METADATA_MONITORING,
  SDWAN_EXPIRED,
  SDWAN_FAILED,
  SDWAN_TERMINAL_PARTIAL
} sdwan_flow_result;

typedef struct {
  uint8_t ip_version;
  uint8_t protocol;
  uint8_t address_a[16];
  uint8_t address_b[16];
  uint16_t port_a;
  uint16_t port_b;
} sdwan_flow_key;

typedef struct {
  sdwan_flow_key key;
  bool source_is_a;
  bool initial_fragment;
  bool unresolved_fragment;
  bool tcp_syn;
  bool tcp_ack;
  bool tcp_fin;
  bool tcp_rst;
  uint32_t tcp_seq;
  uint16_t payload_length;
} sdwan_packet;

typedef struct {
  char name[16];
  uint32_t mark;
} sdwan_path;

typedef struct {
  char name[SDWAN_NAME_LEN];
  uint8_t path_count;
  uint32_t ranked_marks[SDWAN_MAX_PATHS];
} sdwan_class_policy;

typedef struct {
  char application[SDWAN_NAME_LEN];
  uint16_t class_index;
} sdwan_app_policy;

typedef struct {
  char category[SDWAN_NAME_LEN];
  uint16_t class_index;
} sdwan_category_policy;

typedef struct {
  char site[SDWAN_NAME_LEN];
  uint64_t version;
  uint64_t epoch;
  uint64_t created_ms;
  uint64_t expires_ms;
  char generation[SDWAN_NAME_LEN];
  uint64_t catalog_version;
  uint8_t path_count;
  sdwan_path paths[SDWAN_MAX_PATHS];
  uint16_t class_count;
  sdwan_class_policy classes[SDWAN_MAX_CLASSES];
  uint16_t app_count;
  sdwan_app_policy applications[SDWAN_MAX_APPS];
  uint16_t category_count;
  sdwan_category_policy categories[SDWAN_MAX_CATEGORIES];
  uint16_t unknown_class;
  bool fail_open;
} sdwan_policy;

typedef struct {
  pthread_rwlock_t lock;
  sdwan_policy active;
  char expected_site[SDWAN_NAME_LEN];
  uint32_t path_mask;
  bool configured_fail_open;
  atomic_uint_fast64_t accepted;
  atomic_uint_fast64_t rejected_stale;
  atomic_uint_fast64_t rejected_invalid;
} sdwan_policy_store;

typedef struct {
  char site[SDWAN_NAME_LEN];
  uint16_t queue_start;
  uint16_t queue_end;
  uint32_t queue_maxlen;
  int socket_buffer;
  uint32_t path_mask;
  uint32_t terminal_bit;
  uint32_t provisional_bit;
  uint32_t emergency_bit;
  uint32_t fallback_mark;
  uint32_t tcp_budget;
  uint32_t udp_budget;
  uint32_t inspection_timeout_s;
  uint32_t max_flows;
  uint32_t tcp_handshake_timeout_s;
  uint32_t tcp_established_timeout_s;
  uint32_t tcp_closing_timeout_s;
  uint32_t udp_timeout_s;
  uint32_t dns_timeout_s;
  uint32_t metadata_timeout_s;
  uint32_t max_lifetime_s;
  uint32_t overload_circuit_s;
  bool fail_open;
  char policy_socket[108];
  char event_socket[108];
} sdwan_config;

typedef struct sdwan_flow {
  sdwan_flow_key key;
  struct ndpi_flow_struct *ndpi;
  struct sdwan_flow *next;
  uint64_t first_ms;
  uint64_t last_ms;
  uint32_t packets[2];
  uint32_t unique_payload_packets;
  uint32_t highest_end_seq[2];
  uint32_t active_path;
  uint32_t desired_path;
  uint16_t master_protocol;
  uint16_t app_protocol;
  uint16_t protocol_stack[NDPI_PROTOCOL_STACK_SIZE];
  uint16_t protocol_stack_size;
  uint16_t category;
  uint16_t confidence;
  uint16_t fpc_confidence;
  uint8_t protocol;
  uint8_t client_is_a;
  uint8_t beginning_seen;
  uint8_t tcp_state;
  sdwan_flow_result result;
  char application[SDWAN_NAME_LEN];
  char category_name[SDWAN_NAME_LEN];
  char hostname[80];
  char confidence_name[48];
  char fpc_confidence_name[48];
  char completion_reason[48];
} sdwan_flow;

typedef struct {
  size_t bucket_count;
  size_t size;
  size_t max_flows;
  sdwan_flow **buckets;
  uint64_t evicted;
  uint64_t expired_idle;
  uint64_t expired_lifetime;
} sdwan_flow_table;

typedef struct {
  struct ndpi_detection_module_struct *module;
  char revision[64];
} sdwan_ndpi;

typedef struct {
  int type;
  uint16_t queue;
  uint64_t timestamp_ms;
  sdwan_flow_result result;
  uint32_t active_path;
  uint32_t desired_path;
  uint64_t packets;
  uint32_t packets_by_direction[2];
  uint32_t unique_payload_packets;
  uint64_t classification_latency_ms;
  uint16_t confidence;
  uint16_t fpc_confidence;
  uint16_t protocol_stack[NDPI_PROTOCOL_STACK_SIZE];
  uint16_t protocol_stack_size;
  uint64_t flows;
  uint64_t parse_errors;
  uint64_t truncations;
  uint64_t checksum_not_ready;
  uint64_t enobufs;
  uint64_t verdict_errors;
  uint64_t expired_flows;
  uint64_t event_drops;
  uint64_t evicted_flows;
  uint64_t idle_expirations;
  uint64_t lifetime_expirations;
  char application[SDWAN_NAME_LEN];
  char category[SDWAN_NAME_LEN];
  char hostname[80];
  char server_address[INET6_ADDRSTRLEN];
  uint16_t server_port;
  char transport[8];
  char confidence_name[48];
  char fpc_confidence_name[48];
  char reason[48];
} sdwan_event;

typedef struct {
  pthread_mutex_t lock;
  pthread_cond_t ready;
  sdwan_event items[SDWAN_EVENT_CAPACITY];
  size_t head;
  size_t tail;
  size_t count;
  bool stopping;
  int socket_fd;
  char destination[108];
  pthread_t thread;
  atomic_uint_fast64_t dropped;
  atomic_uint_fast64_t sent;
} sdwan_event_queue;

typedef struct {
  uint16_t queue_number;
  sdwan_config *config;
  sdwan_policy_store *policy;
  sdwan_event_queue *events;
  sdwan_ndpi ndpi;
  sdwan_flow_table flows;
  pthread_t thread;
  atomic_uint_fast64_t packets;
  atomic_uint_fast64_t verdict_errors;
  atomic_uint_fast64_t parse_errors;
  atomic_uint_fast64_t truncations;
  atomic_uint_fast64_t checksum_not_ready;
  atomic_uint_fast64_t enobufs;
  atomic_uint_fast64_t expired_flows;
  atomic_uint_fast64_t overload_until_ms;
  atomic_bool ready;
  atomic_bool failed;
} sdwan_worker;

extern volatile sig_atomic_t sdwan_stop;

uint64_t sdwan_now_ms(void);
bool sdwan_parse_packet(const uint8_t *data, size_t length, sdwan_packet *out);
uint64_t sdwan_flow_hash(const sdwan_flow_key *key);
bool sdwan_flow_key_equal(const sdwan_flow_key *a, const sdwan_flow_key *b);

bool sdwan_policy_store_init(sdwan_policy_store *store, const sdwan_config *config);
void sdwan_policy_store_destroy(sdwan_policy_store *store);
bool sdwan_policy_update_json(sdwan_policy_store *store, const char *json, size_t length);
uint32_t sdwan_policy_choose(sdwan_policy_store *store, const char *application,
                             const char *category, uint32_t fallback);
void *sdwan_policy_listener(void *argument);

bool sdwan_ndpi_init(sdwan_ndpi *engine);
void sdwan_ndpi_destroy(sdwan_ndpi *engine);
struct ndpi_flow_struct *sdwan_ndpi_flow_new(void);
void sdwan_ndpi_flow_free(struct ndpi_flow_struct *flow);
ndpi_protocol sdwan_ndpi_process(sdwan_ndpi *engine, sdwan_flow *flow,
                                 const uint8_t *packet, uint16_t length,
                                 uint64_t timestamp_ms, uint8_t direction);
ndpi_protocol sdwan_ndpi_giveup(sdwan_ndpi *engine, sdwan_flow *flow);
void sdwan_ndpi_metadata(sdwan_ndpi *engine, sdwan_flow *flow, ndpi_protocol result);
bool sdwan_ndpi_confidence_authoritative(uint16_t confidence);

bool sdwan_flow_table_init(sdwan_flow_table *table, size_t max_flows);
void sdwan_flow_table_destroy(sdwan_flow_table *table);
sdwan_flow *sdwan_flow_get(sdwan_flow_table *table, const sdwan_packet *packet,
                           uint64_t now_ms, uint32_t fallback_path, bool *created);
typedef void (*sdwan_flow_expiry_observer)(sdwan_flow *flow, bool lifetime,
                                           uint64_t now_ms, void *context);
size_t sdwan_flow_expire(sdwan_flow_table *table, const sdwan_config *config,
                         uint64_t now_ms, sdwan_flow_expiry_observer observer,
                         void *context);

bool sdwan_event_queue_init(sdwan_event_queue *queue, const char *destination);
void sdwan_event_queue_destroy(sdwan_event_queue *queue);
bool sdwan_event_push(sdwan_event_queue *queue, const sdwan_event *event);

bool sdwan_worker_init(sdwan_worker *worker, uint16_t queue_number, sdwan_config *config,
                       sdwan_policy_store *policy, sdwan_event_queue *events);
void sdwan_worker_destroy(sdwan_worker *worker);
void *sdwan_worker_run(void *argument);

#endif
