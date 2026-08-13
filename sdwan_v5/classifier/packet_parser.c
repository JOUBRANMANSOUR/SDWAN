#include "classifier.h"

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>

uint64_t sdwan_now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int compare_endpoint(const uint8_t *a, uint16_t ap, const uint8_t *b,
                            uint16_t bp, size_t address_length) {
  int value = memcmp(a, b, address_length);
  if (value != 0) return value;
  return ap < bp ? -1 : ap > bp;
}

bool sdwan_parse_packet(const uint8_t *data, size_t length, sdwan_packet *out) {
  uint8_t source[16] = {0}, destination[16] = {0};
  uint8_t protocol;
  uint16_t source_port = 0, destination_port = 0;
  size_t offset, address_length;
  memset(out, 0, sizeof(*out));
  if (length < 1) return false;
  out->key.ip_version = data[0] >> 4;
  if (out->key.ip_version == 4) {
    if (length < sizeof(struct iphdr)) return false;
    const struct iphdr *ip = (const struct iphdr *)data;
    offset = (size_t)ip->ihl * 4u;
    if (offset < 20 || offset > length) return false;
    size_t total_length = ntohs(ip->tot_len);
    if (total_length < offset || total_length > length) return false;
    length = total_length;
    memcpy(source, &ip->saddr, 4); memcpy(destination, &ip->daddr, 4);
    protocol = ip->protocol; address_length = 4;
    uint16_t fragment = ntohs(ip->frag_off);
    out->initial_fragment = (fragment & IP_MF) != 0;
    out->unresolved_fragment = (fragment & IP_OFFMASK) != 0;
    if (out->initial_fragment || out->unresolved_fragment) return false;
  } else if (out->key.ip_version == 6) {
    if (length < sizeof(struct ip6_hdr)) return false;
    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)data;
    memcpy(source, &ip6->ip6_src, 16); memcpy(destination, &ip6->ip6_dst, 16);
    protocol = ip6->ip6_nxt; offset = sizeof(struct ip6_hdr); address_length = 16;
    size_t total_length = sizeof(struct ip6_hdr) + ntohs(ip6->ip6_plen);
    if (total_length > length || total_length < sizeof(struct ip6_hdr)) return false;
    length = total_length;
    if (protocol == IPPROTO_FRAGMENT) { out->unresolved_fragment = true; return false; }
    if (protocol == IPPROTO_HOPOPTS || protocol == IPPROTO_ROUTING ||
        protocol == IPPROTO_DSTOPTS || protocol == IPPROTO_AH)
      return false;
  } else return false;
  if (out->unresolved_fragment) return false;
  if (protocol == IPPROTO_TCP) {
    if (offset + sizeof(struct tcphdr) > length) return false;
    const struct tcphdr *tcp = (const struct tcphdr *)(data + offset);
    size_t tcp_length = (size_t)tcp->doff * 4u;
    if (tcp_length < 20 || offset + tcp_length > length) return false;
    source_port = ntohs(tcp->source); destination_port = ntohs(tcp->dest);
    out->tcp_syn = tcp->syn; out->tcp_ack = tcp->ack;
    out->tcp_fin = tcp->fin; out->tcp_rst = tcp->rst;
    out->tcp_seq = ntohl(tcp->seq);
    out->payload_length = (uint16_t)(length - offset - tcp_length);
  } else if (protocol == IPPROTO_UDP) {
    if (offset + sizeof(struct udphdr) > length) return false;
    const struct udphdr *udp = (const struct udphdr *)(data + offset);
    size_t udp_length = ntohs(udp->len);
    if (udp_length < sizeof(struct udphdr) || offset + udp_length > length) return false;
    source_port = ntohs(udp->source); destination_port = ntohs(udp->dest);
    out->payload_length = (uint16_t)(udp_length - sizeof(struct udphdr));
  }
  out->key.protocol = protocol;
  int order = compare_endpoint(source, source_port, destination, destination_port, address_length);
  out->source_is_a = order <= 0;
  const uint8_t *a = out->source_is_a ? source : destination;
  const uint8_t *b = out->source_is_a ? destination : source;
  memcpy(out->key.address_a, a, address_length); memcpy(out->key.address_b, b, address_length);
  out->key.port_a = out->source_is_a ? source_port : destination_port;
  out->key.port_b = out->source_is_a ? destination_port : source_port;
  return true;
}

uint64_t sdwan_flow_hash(const sdwan_flow_key *key) {
  const uint8_t *bytes = (const uint8_t *)key;
  uint64_t hash = 1469598103934665603ULL;
  for (size_t i = 0; i < sizeof(*key); ++i) { hash ^= bytes[i]; hash *= 1099511628211ULL; }
  return hash;
}

bool sdwan_flow_key_equal(const sdwan_flow_key *a, const sdwan_flow_key *b) {
  return memcmp(a, b, sizeof(*a)) == 0;
}
