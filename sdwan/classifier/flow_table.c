#include "classifier.h"

#include <stdlib.h>
#include <string.h>

static void free_record(sdwan_flow *flow) {
  if (!flow) return;
  sdwan_ndpi_flow_free(flow->ndpi);
  free(flow);
}

bool sdwan_flow_table_init(sdwan_flow_table *table, size_t max_flows) {
  memset(table, 0, sizeof(*table));
  table->bucket_count = 4099;
  table->max_flows = max_flows;
  table->buckets = calloc(table->bucket_count, sizeof(*table->buckets));
  return table->buckets != NULL;
}

void sdwan_flow_table_destroy(sdwan_flow_table *table) {
  if (!table->buckets) return;
  for (size_t i = 0; i < table->bucket_count; ++i) {
    sdwan_flow *item = table->buckets[i];
    while (item) { sdwan_flow *next = item->next; free_record(item); item = next; }
  }
  free(table->buckets); memset(table, 0, sizeof(*table));
}

static void evict_oldest(sdwan_flow_table *table) {
  sdwan_flow **oldest_link = NULL;
  uint64_t oldest = UINT64_MAX;
  for (size_t i = 0; i < table->bucket_count; ++i) {
    for (sdwan_flow **link = &table->buckets[i]; *link; link = &(*link)->next) {
      if ((*link)->last_ms < oldest) { oldest = (*link)->last_ms; oldest_link = link; }
    }
  }
  if (oldest_link) {
    sdwan_flow *victim = *oldest_link; *oldest_link = victim->next;
    free_record(victim); table->size--; table->evicted++;
  }
}

sdwan_flow *sdwan_flow_get(sdwan_flow_table *table, const sdwan_packet *packet,
                           uint64_t now_ms, uint32_t fallback_path, bool *created) {
  size_t bucket = sdwan_flow_hash(&packet->key) % table->bucket_count;
  for (sdwan_flow *item = table->buckets[bucket]; item; item = item->next) {
    if (sdwan_flow_key_equal(&item->key, &packet->key)) { *created = false; return item; }
  }
  if (table->size >= table->max_flows) evict_oldest(table);
  sdwan_flow *item = calloc(1, sizeof(*item));
  if (!item) return NULL;
  item->ndpi = sdwan_ndpi_flow_new();
  if (!item->ndpi) { free(item); return NULL; }
  item->key = packet->key; item->first_ms = item->last_ms = now_ms;
  item->active_path = fallback_path; item->desired_path = fallback_path;
  item->protocol = packet->key.protocol;
  item->client_is_a = packet->source_is_a;
  if (item->protocol == IPPROTO_TCP && packet->tcp_syn && packet->tcp_ack)
    item->client_is_a = !packet->source_is_a;
  item->beginning_seen = packet->tcp_syn && !packet->tcp_ack;
  item->result = SDWAN_INSPECTING;
  item->next = table->buckets[bucket]; table->buckets[bucket] = item; table->size++;
  *created = true; return item;
}

static uint64_t timeout_ms(const sdwan_flow *flow, const sdwan_config *config) {
  if (flow->result == SDWAN_METADATA_MONITORING)
    return (uint64_t)config->metadata_timeout_s * 1000u;
  if (flow->protocol == IPPROTO_UDP) {
    if (flow->app_protocol == NDPI_PROTOCOL_DNS ||
        flow->master_protocol == NDPI_PROTOCOL_DNS)
      return (uint64_t)config->dns_timeout_s * 1000u;
    return (uint64_t)config->udp_timeout_s * 1000u;
  }
  if (flow->protocol == IPPROTO_TCP) {
    if (flow->tcp_state == 0) return (uint64_t)config->tcp_handshake_timeout_s * 1000u;
    if (flow->tcp_state >= 2) return (uint64_t)config->tcp_closing_timeout_s * 1000u;
    return (uint64_t)config->tcp_established_timeout_s * 1000u;
  }
  return (uint64_t)config->udp_timeout_s * 1000u;
}

size_t sdwan_flow_expire(sdwan_flow_table *table, const sdwan_config *config,
                         uint64_t now_ms, sdwan_flow_expiry_observer observer,
                         void *context) {
  size_t expired = 0;
  for (size_t i = 0; i < table->bucket_count; ++i) {
    sdwan_flow **link = &table->buckets[i];
    while (*link) {
      sdwan_flow *item = *link;
      bool idle = now_ms - item->last_ms >= timeout_ms(item, config);
      bool lifetime = now_ms - item->first_ms >= (uint64_t)config->max_lifetime_s * 1000u;
      if (idle || lifetime) {
        if (observer) observer(item, lifetime, now_ms, context);
        *link = item->next; item->result = SDWAN_EXPIRED; free_record(item);
        table->size--; expired++;
        if (lifetime) table->expired_lifetime++;
        else table->expired_idle++;
      } else link = &item->next;
    }
  }
  return expired;
}
