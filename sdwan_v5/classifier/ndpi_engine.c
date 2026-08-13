#include "classifier.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool sdwan_ndpi_init(sdwan_ndpi *engine) {
  memset(engine, 0, sizeof(*engine));
  engine->module = ndpi_init_detection_module(NULL);
  if (!engine->module) return false;
  if (ndpi_finalize_initialization(engine->module) != 0) {
    ndpi_exit_detection_module(engine->module); engine->module = NULL; return false;
  }
  snprintf(engine->revision, sizeof(engine->revision), "%s", ndpi_revision());
  if (strstr(engine->revision, "5.0") == NULL) {
    fprintf(stderr, "unsupported nDPI revision: %s (expected pinned 5.0)\n", engine->revision);
    ndpi_exit_detection_module(engine->module); engine->module = NULL; return false;
  }
  return ndpi_get_num_protocols(engine->module) > 0;
}

void sdwan_ndpi_destroy(sdwan_ndpi *engine) {
  if (engine->module) ndpi_exit_detection_module(engine->module);
  memset(engine, 0, sizeof(*engine));
}

struct ndpi_flow_struct *sdwan_ndpi_flow_new(void) {
  struct ndpi_flow_struct *flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
  if (flow) memset(flow, 0, SIZEOF_FLOW_STRUCT);
  return flow;
}

void sdwan_ndpi_flow_free(struct ndpi_flow_struct *flow) {
  if (flow) ndpi_flow_free(flow);
}

ndpi_protocol sdwan_ndpi_process(sdwan_ndpi *engine, sdwan_flow *flow,
                                 const uint8_t *packet, uint16_t length,
                                 uint64_t timestamp_ms, uint8_t direction) {
  struct ndpi_flow_input_info input = {
    .in_pkt_dir = direction ? NDPI_IN_PKT_DIR_S_TO_C : NDPI_IN_PKT_DIR_C_TO_S,
    .seen_flow_beginning = flow->beginning_seen
      ? NDPI_FLOW_BEGINNING_SEEN : NDPI_FLOW_BEGINNING_UNKNOWN,
  };
  return ndpi_detection_process_packet(
      engine->module, flow->ndpi, packet, length, timestamp_ms, &input);
}

ndpi_protocol sdwan_ndpi_giveup(sdwan_ndpi *engine, sdwan_flow *flow) {
  return ndpi_detection_giveup(engine->module, flow->ndpi);
}

void sdwan_ndpi_metadata(sdwan_ndpi *engine, sdwan_flow *flow, ndpi_protocol result) {
  flow->master_protocol = result.proto.master_protocol;
  flow->app_protocol = result.proto.app_protocol;
  flow->protocol_stack_size = result.protocol_stack.protos_num;
  if (flow->protocol_stack_size > NDPI_PROTOCOL_STACK_SIZE)
    flow->protocol_stack_size = NDPI_PROTOCOL_STACK_SIZE;
  for (uint16_t i = 0; i < flow->protocol_stack_size; ++i)
    flow->protocol_stack[i] = result.protocol_stack.protos[i];
  flow->category = result.category;
  flow->confidence = flow->ndpi->confidence;
  flow->fpc_confidence = result.fpc.confidence;
  uint16_t name_id = flow->app_protocol != NDPI_PROTOCOL_UNKNOWN
                         ? flow->app_protocol : flow->master_protocol;
  const char *name = ndpi_get_proto_name(engine->module, name_id);
  const char *category = ndpi_category_get_name(engine->module, result.category);
  snprintf(flow->application, sizeof(flow->application), "%s", name ? name : "Unknown");
  snprintf(flow->category_name, sizeof(flow->category_name), "%s", category ? category : "Unspecified");
  snprintf(flow->hostname, sizeof(flow->hostname), "%s", flow->ndpi->host_server_name);
  snprintf(flow->confidence_name, sizeof(flow->confidence_name), "%s",
           ndpi_confidence_get_name(flow->ndpi->confidence));
  snprintf(flow->fpc_confidence_name, sizeof(flow->fpc_confidence_name), "%s",
           ndpi_fpc_confidence_get_name(result.fpc.confidence));
}

bool sdwan_ndpi_confidence_authoritative(uint16_t confidence) {
  return confidence == NDPI_CONFIDENCE_DPI ||
         confidence == NDPI_CONFIDENCE_DPI_CACHE ||
         confidence == NDPI_CONFIDENCE_CUSTOM_RULE;
}
