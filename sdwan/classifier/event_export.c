#include "classifier.h"

#include <json-c/json.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>

static void *export_events(void *argument) {
  sdwan_event_queue *queue = argument;
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  snprintf(address.sun_path, sizeof(address.sun_path), "%s", queue->destination);
  while (true) {
    pthread_mutex_lock(&queue->lock);
    while (!queue->count && !queue->stopping) pthread_cond_wait(&queue->ready, &queue->lock);
    if (!queue->count && queue->stopping) { pthread_mutex_unlock(&queue->lock); break; }
    sdwan_event event = queue->items[queue->tail];
    queue->tail = (queue->tail + 1) % SDWAN_EVENT_CAPACITY; queue->count--;
    pthread_mutex_unlock(&queue->lock);
    struct json_object *root = json_object_new_object();
    json_object_object_add(root, "type", json_object_new_string(event.type ? "stats" : "flow"));
    json_object_object_add(root, "queue", json_object_new_int(event.queue));
    json_object_object_add(root, "timestamp_ms", json_object_new_int64((int64_t)event.timestamp_ms));
    json_object_object_add(root, "result", json_object_new_int(event.result));
    json_object_object_add(root, "active_path", json_object_new_int64(event.active_path));
    json_object_object_add(root, "desired_path", json_object_new_int64(event.desired_path));
    json_object_object_add(root, "packets", json_object_new_int64(event.packets));
    struct json_object *directions = json_object_new_array();
    json_object_array_add(directions, json_object_new_int64(event.packets_by_direction[0]));
    json_object_array_add(directions, json_object_new_int64(event.packets_by_direction[1]));
    json_object_object_add(root, "packets_by_direction", directions);
    json_object_object_add(root, "unique_payload_packets", json_object_new_int64(event.unique_payload_packets));
    json_object_object_add(root, "classification_latency_ms", json_object_new_int64(event.classification_latency_ms));
    json_object_object_add(root, "native_confidence", json_object_new_int(event.confidence));
    json_object_object_add(root, "native_confidence_name", json_object_new_string(event.confidence_name));
    json_object_object_add(root, "fpc_confidence", json_object_new_int(event.fpc_confidence));
    json_object_object_add(root, "fpc_confidence_name", json_object_new_string(event.fpc_confidence_name));
    struct json_object *stack = json_object_new_array();
    for (uint16_t i = 0; i < event.protocol_stack_size; ++i)
      json_object_array_add(stack, json_object_new_int(event.protocol_stack[i]));
    json_object_object_add(root, "protocol_stack", stack);
    json_object_object_add(root, "active_flows", json_object_new_int64(event.flows));
    json_object_object_add(root, "parse_errors", json_object_new_int64(event.parse_errors));
    json_object_object_add(root, "truncations", json_object_new_int64(event.truncations));
    json_object_object_add(root, "checksum_not_ready", json_object_new_int64(event.checksum_not_ready));
    json_object_object_add(root, "enobufs", json_object_new_int64(event.enobufs));
    json_object_object_add(root, "verdict_errors", json_object_new_int64(event.verdict_errors));
    json_object_object_add(root, "expired_flows", json_object_new_int64(event.expired_flows));
    json_object_object_add(root, "event_drops", json_object_new_int64(event.event_drops));
    json_object_object_add(root, "evicted_flows", json_object_new_int64(event.evicted_flows));
    json_object_object_add(root, "idle_expirations", json_object_new_int64(event.idle_expirations));
    json_object_object_add(root, "lifetime_expirations", json_object_new_int64(event.lifetime_expirations));
    json_object_object_add(root, "application", json_object_new_string(event.application));
    json_object_object_add(root, "category", json_object_new_string(event.category));
    json_object_object_add(root, "hostname", json_object_new_string(event.hostname));
    json_object_object_add(root, "server_address", json_object_new_string(event.server_address));
    json_object_object_add(root, "server_port", json_object_new_int(event.server_port));
    json_object_object_add(root, "transport", json_object_new_string(event.transport));
    json_object_object_add(root, "reason", json_object_new_string(event.reason));
    const char *text = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    ssize_t sent = sendto(queue->socket_fd, text, strlen(text), MSG_DONTWAIT,
                          (struct sockaddr *)&address, sizeof(address));
    if (sent < 0) atomic_fetch_add(&queue->dropped, 1); else atomic_fetch_add(&queue->sent, 1);
    json_object_put(root);
  }
  return NULL;
}

bool sdwan_event_queue_init(sdwan_event_queue *queue, const char *destination) {
  memset(queue, 0, sizeof(*queue));
  queue->socket_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
  if (queue->socket_fd < 0) return false;
  snprintf(queue->destination, sizeof(queue->destination), "%s", destination);
  pthread_mutex_init(&queue->lock, NULL); pthread_cond_init(&queue->ready, NULL);
  if (pthread_create(&queue->thread, NULL, export_events, queue) == 0) return true;
  pthread_cond_destroy(&queue->ready); pthread_mutex_destroy(&queue->lock);
  close(queue->socket_fd); queue->socket_fd = -1; return false;
}

bool sdwan_event_push(sdwan_event_queue *queue, const sdwan_event *event) {
  bool accepted = false; pthread_mutex_lock(&queue->lock);
  if (queue->count < SDWAN_EVENT_CAPACITY) {
    queue->items[queue->head] = *event; queue->head = (queue->head + 1) % SDWAN_EVENT_CAPACITY;
    queue->count++; accepted = true; pthread_cond_signal(&queue->ready);
  } else atomic_fetch_add(&queue->dropped, 1);
  pthread_mutex_unlock(&queue->lock); return accepted;
}

void sdwan_event_queue_destroy(sdwan_event_queue *queue) {
  pthread_mutex_lock(&queue->lock); queue->stopping = true; pthread_cond_signal(&queue->ready);
  pthread_mutex_unlock(&queue->lock); pthread_join(queue->thread, NULL);
  close(queue->socket_fd); pthread_cond_destroy(&queue->ready); pthread_mutex_destroy(&queue->lock);
}
