#include "classifier.h"

#include <assert.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>

static void ipv4_tcp(uint8_t *packet, uint32_t source, uint32_t destination,
                     uint16_t source_port, uint16_t destination_port, bool reverse) {
  memset(packet, 0, 40);
  struct iphdr *ip = (struct iphdr *)packet;
  ip->version = 4; ip->ihl = 5; ip->protocol = IPPROTO_TCP;
  ip->tot_len = htons(40);
  ip->saddr = htonl(reverse ? destination : source);
  ip->daddr = htonl(reverse ? source : destination);
  struct tcphdr *tcp = (struct tcphdr *)(packet + 20);
  tcp->source = htons(reverse ? destination_port : source_port);
  tcp->dest = htons(reverse ? source_port : destination_port);
  tcp->doff = 5; tcp->syn = true; tcp->ack = reverse;
}

static void test_bidirectional_key(void) {
  uint8_t forward[40], reverse[40];
  sdwan_packet left, right;
  ipv4_tcp(forward, 0x0a01000b, 0x0a02000b, 40000, 443, false);
  ipv4_tcp(reverse, 0x0a01000b, 0x0a02000b, 40000, 443, true);
  assert(sdwan_parse_packet(forward, sizeof(forward), &left));
  assert(sdwan_parse_packet(reverse, sizeof(reverse), &right));
  assert(sdwan_flow_key_equal(&left.key, &right.key));
  assert(left.source_is_a != right.source_is_a);
}

static void test_ipv6_udp_and_fragment_rejection(void) {
  uint8_t packet[48] = {0};
  struct ip6_hdr *ip = (struct ip6_hdr *)packet;
  ip->ip6_vfc = 0x60; ip->ip6_nxt = IPPROTO_UDP; ip->ip6_plen = htons(8);
  ip->ip6_src.s6_addr[15] = 1; ip->ip6_dst.s6_addr[15] = 2;
  struct udphdr *udp = (struct udphdr *)(packet + 40);
  udp->source = htons(50000); udp->dest = htons(53); udp->len = htons(8);
  sdwan_packet parsed;
  assert(sdwan_parse_packet(packet, sizeof(packet), &parsed));
  assert(parsed.key.ip_version == 6 && parsed.key.protocol == IPPROTO_UDP);
  ip->ip6_nxt = IPPROTO_FRAGMENT;
  assert(!sdwan_parse_packet(packet, sizeof(packet), &parsed));
}

static void test_noninitial_ipv4_fragment_rejected(void) {
  uint8_t packet[40]; sdwan_packet parsed;
  ipv4_tcp(packet, 0x0a01000b, 0x0a02000b, 40000, 443, false);
  ((struct iphdr *)packet)->frag_off = htons(1);
  assert(!sdwan_parse_packet(packet, sizeof(packet), &parsed));
  ((struct iphdr *)packet)->frag_off = htons(IP_MF);
  assert(!sdwan_parse_packet(packet, sizeof(packet), &parsed));
  assert(!sdwan_parse_packet(packet, 3, &parsed));
}

int main(void) {
  test_bidirectional_key();
  test_ipv6_udp_and_fragment_rejection();
  test_noninitial_ipv4_fragment_rejected();
  puts("packet parser tests passed");
  return 0;
}
