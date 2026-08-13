#include "classifier.h"

#include <errno.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

typedef struct {
  sdwan_worker *worker;
  struct mnl_socket *socket;
} queue_context;

static void terminal_event(sdwan_worker *worker, const sdwan_flow *flow, uint64_t now) {
  sdwan_event event = {.queue = worker->queue_number, .timestamp_ms = now,
    .result = flow->result, .active_path = flow->active_path,
    .desired_path = flow->desired_path,
    .packets = flow->packets[0] + flow->packets[1],
    .packets_by_direction = {flow->packets[0], flow->packets[1]},
    .unique_payload_packets = flow->unique_payload_packets,
    .classification_latency_ms = now - flow->first_ms,
    .confidence = flow->confidence, .fpc_confidence = flow->fpc_confidence,
    .protocol_stack_size = flow->protocol_stack_size};
  for (uint16_t i = 0; i < flow->protocol_stack_size; ++i)
    event.protocol_stack[i] = flow->protocol_stack[i];
  const uint8_t *server_address = flow->client_is_a
    ? flow->key.address_b : flow->key.address_a;
  event.server_port = flow->client_is_a ? flow->key.port_b : flow->key.port_a;
  inet_ntop(flow->key.ip_version == 4 ? AF_INET : AF_INET6,
            server_address, event.server_address, sizeof(event.server_address));
  snprintf(event.transport, sizeof(event.transport), "%s",
           flow->protocol == IPPROTO_TCP ? "tcp" :
           flow->protocol == IPPROTO_UDP ? "udp" : "other");
  snprintf(event.application, sizeof(event.application), "%s", flow->application);
  snprintf(event.category, sizeof(event.category), "%s", flow->category_name);
  snprintf(event.hostname, sizeof(event.hostname), "%s", flow->hostname);
  snprintf(event.confidence_name, sizeof(event.confidence_name), "%s", flow->confidence_name);
  snprintf(event.fpc_confidence_name, sizeof(event.fpc_confidence_name), "%s", flow->fpc_confidence_name);
  snprintf(event.reason, sizeof(event.reason), "%s", flow->completion_reason);
  sdwan_event_push(worker->events, &event);
}

static void expiration_event(sdwan_flow *flow, bool lifetime, uint64_t now,
                             void *context) {
  sdwan_worker *worker = context;
  ndpi_protocol result = sdwan_ndpi_giveup(&worker->ndpi, flow);
  sdwan_ndpi_metadata(&worker->ndpi, flow, result);
  bool identified = flow->app_protocol != NDPI_PROTOCOL_UNKNOWN ||
                    flow->master_protocol != NDPI_PROTOCOL_UNKNOWN;
  flow->desired_path = flow->active_path;
  if (result.state == NDPI_STATE_MONITORING)
    flow->result = SDWAN_METADATA_MONITORING;
  else if (result.state == NDPI_STATE_CLASSIFIED)
    flow->result = SDWAN_CLASSIFIED;
  else if (identified)
    flow->result = SDWAN_TERMINAL_PARTIAL;
  else {
    flow->result = SDWAN_TERMINAL_UNKNOWN;
    snprintf(flow->application, sizeof(flow->application), "Unknown");
  }
  snprintf(flow->completion_reason, sizeof(flow->completion_reason), "%s",
           lifetime ? "lifetime-expired" : "idle-expired");
  terminal_event(worker, flow, now);
}

static void stats_event(sdwan_worker *worker, uint64_t now) {
  sdwan_event event = {.type = 1, .queue = worker->queue_number, .timestamp_ms = now,
    .packets = atomic_load(&worker->packets), .flows = worker->flows.size,
    .parse_errors = atomic_load(&worker->parse_errors),
    .truncations = atomic_load(&worker->truncations),
    .checksum_not_ready = atomic_load(&worker->checksum_not_ready),
    .enobufs = atomic_load(&worker->enobufs),
    .verdict_errors = atomic_load(&worker->verdict_errors),
    .expired_flows = atomic_load(&worker->expired_flows),
    .event_drops = atomic_load(&worker->events->dropped),
    .evicted_flows = worker->flows.evicted,
    .idle_expirations = worker->flows.expired_idle,
    .lifetime_expirations = worker->flows.expired_lifetime};
  snprintf(event.reason, sizeof(event.reason), "worker-stats");
  sdwan_event_push(worker->events, &event);
}

static int send_verdict(queue_context *context, uint32_t id, uint32_t verdict,
                        uint32_t mark) {
  char buffer[MNL_SOCKET_BUFFER_SIZE];
  struct nlmsghdr *message = nfq_nlmsg_put(
      buffer, NFQNL_MSG_VERDICT, context->worker->queue_number);
  nfq_nlmsg_verdict_put(message, id, verdict);
  mnl_attr_put_u32(message, NFQA_MARK, htonl(mark));
  int result = mnl_socket_sendto(context->socket, message, message->nlmsg_len);
  if (result < 0) atomic_fetch_add(&context->worker->verdict_errors, 1);
  return result;
}

static int process_packet(queue_context *context, uint32_t id, uint32_t incoming_mark,
                          const uint8_t *payload, size_t length, uint32_t captured_length,
                          uint32_t skb_info) {
  sdwan_worker *worker = context->worker;
  uint32_t path = incoming_mark & worker->config->path_mask;
  if (!path) path = worker->config->fallback_mark & worker->config->path_mask;
  uint32_t preserved_mark = incoming_mark & ~(worker->config->path_mask |
      worker->config->terminal_bit | worker->config->provisional_bit);
  uint32_t verdict_mark = preserved_mark | path | worker->config->provisional_bit;
  atomic_fetch_add(&worker->packets, 1);
  if (skb_info & NFQA_SKB_CSUMNOTREADY)
    atomic_fetch_add(&worker->checksum_not_ready, 1);
  uint64_t now = sdwan_now_ms();
  if (worker->config->fail_open && now < atomic_load(&worker->overload_until_ms))
    return send_verdict(context, id, NF_ACCEPT, verdict_mark);
  if (!payload || !length || (captured_length && captured_length != length)) {
    if (captured_length && captured_length != length)
      atomic_fetch_add(&worker->truncations, 1);
    else atomic_fetch_add(&worker->parse_errors, 1);
    return send_verdict(
        context, id, worker->config->fail_open ? NF_ACCEPT : NF_DROP, verdict_mark);
  }
  sdwan_packet packet;
  if (!sdwan_parse_packet(payload, length, &packet)) {
    atomic_fetch_add(&worker->parse_errors, 1);
    return send_verdict(
        context, id, worker->config->fail_open ? NF_ACCEPT : NF_DROP, verdict_mark);
  }
  bool created = false;
  sdwan_flow *flow = sdwan_flow_get(&worker->flows, &packet, now, path, &created);
  if (!flow)
    return send_verdict(
        context, id, worker->config->fail_open ? NF_ACCEPT : NF_DROP, verdict_mark);
  uint8_t direction = packet.source_is_a == flow->client_is_a ? 0 : 1;
  flow->packets[direction]++; flow->last_ms = now;
  if (packet.key.protocol == IPPROTO_TCP) {
    if (packet.tcp_syn && packet.tcp_ack) flow->tcp_state = 1;
    else if (packet.tcp_ack && flow->tcp_state == 0) flow->tcp_state = 1;
    if (packet.tcp_fin || packet.tcp_rst) flow->tcp_state = 2;
  }
  bool new_payload = packet.payload_length > 0;
  if (packet.key.protocol == IPPROTO_TCP && new_payload) {
    uint32_t end = packet.tcp_seq + packet.payload_length;
    if (end <= flow->highest_end_seq[direction]) new_payload = false;
    else flow->highest_end_seq[direction] = end;
  }
  if (new_payload) flow->unique_payload_packets++;
  ndpi_protocol result = sdwan_ndpi_process(
      &worker->ndpi, flow, payload, (uint16_t)length, now, direction);
  sdwan_ndpi_metadata(&worker->ndpi, flow, result);
  if (result.state == NDPI_STATE_PARTIAL) flow->result = SDWAN_PARTIAL;
  bool terminal = result.state == NDPI_STATE_CLASSIFIED || result.state == NDPI_STATE_MONITORING;
  uint32_t budget = packet.key.protocol == IPPROTO_TCP
    ? worker->config->tcp_budget : worker->config->udp_budget;
  bool budget_exhausted = flow->unique_payload_packets >= budget;
  bool time_exhausted = now - flow->first_ms >=
    (uint64_t)worker->config->inspection_timeout_s * 1000u;
  if (!terminal && (budget_exhausted || time_exhausted)) {
    result = sdwan_ndpi_giveup(&worker->ndpi, flow);
    sdwan_ndpi_metadata(&worker->ndpi, flow, result);
    terminal = true;
    snprintf(flow->completion_reason, sizeof(flow->completion_reason), "%s",
             budget_exhausted ? "protocol-budget" : "inspection-timeout");
  } else if (result.state == NDPI_STATE_MONITORING) {
    snprintf(flow->completion_reason, sizeof(flow->completion_reason), "inline-monitoring-truncated");
  } else if (terminal) {
    snprintf(flow->completion_reason, sizeof(flow->completion_reason), "ndpi-classified");
  }
  bool identified = flow->app_protocol != NDPI_PROTOCOL_UNKNOWN ||
                    flow->master_protocol != NDPI_PROTOCOL_UNKNOWN;
  /* nDPI emits metadata only. Edge Agent owns SLA/egress/target selection. */
  flow->desired_path = flow->active_path;
  if (terminal) {
    if (!identified) flow->result = SDWAN_TERMINAL_UNKNOWN;
    else if (result.state == NDPI_STATE_MONITORING)
      flow->result = SDWAN_METADATA_MONITORING;
    else if (result.state == NDPI_STATE_CLASSIFIED)
      flow->result = SDWAN_CLASSIFIED;
    else flow->result = SDWAN_TERMINAL_PARTIAL;
    if (!identified) snprintf(flow->application, sizeof(flow->application), "Unknown");
    verdict_mark = preserved_mark | flow->active_path | worker->config->terminal_bit;
    terminal_event(worker, flow, now);
  } else {
    verdict_mark = preserved_mark | flow->active_path | worker->config->provisional_bit;
  }
  return send_verdict(context, id, NF_ACCEPT, verdict_mark);
}

static int packet_callback(const struct nlmsghdr *message, void *argument) {
  queue_context *context = argument;
  struct nlattr *attributes[NFQA_MAX + 1] = {0};
  if (nfq_nlmsg_parse(message, attributes) < 0 || !attributes[NFQA_PACKET_HDR]) {
    atomic_fetch_add(&context->worker->parse_errors, 1);
    return MNL_CB_OK;
  }
  const struct nfqnl_msg_packet_hdr *header =
    mnl_attr_get_payload(attributes[NFQA_PACKET_HDR]);
  uint32_t id = ntohl(header->packet_id);
  const uint8_t *payload = attributes[NFQA_PAYLOAD]
    ? mnl_attr_get_payload(attributes[NFQA_PAYLOAD]) : NULL;
  size_t length = attributes[NFQA_PAYLOAD]
    ? mnl_attr_get_payload_len(attributes[NFQA_PAYLOAD]) : 0;
  uint32_t captured_length = attributes[NFQA_CAP_LEN]
    ? ntohl(mnl_attr_get_u32(attributes[NFQA_CAP_LEN])) : (uint32_t)length;
  uint32_t mark = attributes[NFQA_MARK]
    ? ntohl(mnl_attr_get_u32(attributes[NFQA_MARK])) : 0;
  uint32_t skb_info = attributes[NFQA_SKB_INFO]
    ? ntohl(mnl_attr_get_u32(attributes[NFQA_SKB_INFO])) : 0;
  process_packet(context, id, mark, payload, length, captured_length, skb_info);
  return MNL_CB_OK;
}

bool sdwan_worker_init(sdwan_worker *worker, uint16_t number, sdwan_config *config,
                       sdwan_policy_store *policy, sdwan_event_queue *events) {
  memset(worker, 0, sizeof(*worker)); worker->queue_number = number;
  worker->config = config; worker->policy = policy; worker->events = events;
  if (!sdwan_ndpi_init(&worker->ndpi)) return false;
  size_t count = (size_t)(config->queue_end - config->queue_start + 1);
  size_t per_worker = (config->max_flows + count - 1) / count;
  if (!sdwan_flow_table_init(&worker->flows, per_worker)) {
    sdwan_ndpi_destroy(&worker->ndpi); return false;
  }
  return true;
}

void sdwan_worker_destroy(sdwan_worker *worker) {
  sdwan_flow_table_destroy(&worker->flows); sdwan_ndpi_destroy(&worker->ndpi);
}

static bool configure_queue(struct mnl_socket *socket, uint16_t queue_number,
                            const sdwan_config *config) {
  char buffer[MNL_SOCKET_BUFFER_SIZE];
  struct nlmsghdr *message = nfq_nlmsg_put(buffer, NFQNL_MSG_CONFIG, queue_number);
  nfq_nlmsg_cfg_put_cmd(message, AF_INET, NFQNL_CFG_CMD_BIND);
  if (mnl_socket_sendto(socket, message, message->nlmsg_len) < 0) return false;
  message = nfq_nlmsg_put(buffer, NFQNL_MSG_CONFIG, queue_number);
  nfq_nlmsg_cfg_put_params(message, NFQNL_COPY_PACKET, 0xffff);
  mnl_attr_put_u32(message, NFQA_CFG_QUEUE_MAXLEN, htonl(config->queue_maxlen));
  uint32_t flags = NFQA_CFG_F_GSO;
  if (config->fail_open) flags |= NFQA_CFG_F_FAIL_OPEN;
  mnl_attr_put_u32(message, NFQA_CFG_FLAGS, htonl(flags));
  mnl_attr_put_u32(message, NFQA_CFG_MASK, htonl(flags));
  return mnl_socket_sendto(socket, message, message->nlmsg_len) >= 0;
}

void *sdwan_worker_run(void *argument) {
  sdwan_worker *worker = argument;
  struct mnl_socket *socket = mnl_socket_open(NETLINK_NETFILTER);
  if (!socket || mnl_socket_bind(socket, 0, MNL_SOCKET_AUTOPID) < 0 ||
      !configure_queue(socket, worker->queue_number, worker->config)) {
    atomic_store(&worker->failed, true);
    if (socket) mnl_socket_close(socket);
    return NULL;
  }
  int fd = mnl_socket_get_fd(socket);
  int size = worker->config->socket_buffer;
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
  struct timeval timeout = {.tv_sec = 1};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  size_t buffer_size = 0xffffu + MNL_SOCKET_BUFFER_SIZE / 2u;
  char *buffer = malloc(buffer_size);
  if (!buffer) {
    atomic_store(&worker->failed, true); mnl_socket_close(socket); return NULL;
  }
  queue_context context = {.worker = worker, .socket = socket};
  unsigned int port_id = mnl_socket_get_portid(socket);
  atomic_store(&worker->ready, true);
  uint64_t last_expiry = sdwan_now_ms();
  while (!sdwan_stop) {
    int count = mnl_socket_recvfrom(socket, buffer, buffer_size);
    if (count > 0) {
      if (mnl_cb_run(buffer, count, 0, port_id, packet_callback, &context) < 0 &&
          errno != EINTR)
        atomic_fetch_add(&worker->parse_errors, 1);
    } else if (count < 0 && errno == ENOBUFS) {
      atomic_fetch_add(&worker->enobufs, 1);
      atomic_store(&worker->overload_until_ms,
                   sdwan_now_ms() + (uint64_t)worker->config->overload_circuit_s * 1000u);
    } else if (count < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
      usleep(1000);
    }
    uint64_t now = sdwan_now_ms();
    if (now - last_expiry >= 1000) {
      size_t expired = sdwan_flow_expire(&worker->flows, worker->config, now,
                                         expiration_event, worker);
      atomic_fetch_add(&worker->expired_flows, expired);
      stats_event(worker, now); last_expiry = now;
    }
  }
  free(buffer); mnl_socket_close(socket); return NULL;
}
