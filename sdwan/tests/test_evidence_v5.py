from __future__ import annotations
import unittest
from sdwan.management.evidence import EvidenceValidator, render_verified_answer

BUNDLE={"bundle_id":"bundle-1","payload":{"facts":[{"fact_id":"f-route","fact_kind":"selected_routing_table","value":1101},{"fact_id":"f-interface","fact_kind":"output_interface","value":"wg-h1-mpls"}],"sources":[{"source_id":"s1"}],"unknowns":[],"limitations":[]}}
class EvidenceTests(unittest.TestCase):
    def setUp(self): self.validator=EvidenceValidator()
    def test_valid_operational_claims_render_only_fact_values(self):
        answer={"answer_type":"operational","summary":"ignored","claims":[{"claim_id":"c1","claim_type":"routing_table","fact_ids":["f-route"],"explanation":"ignored"}],"unknowns":[],"limitations":[]}
        result=self.validator.validate(answer,BUNDLE)
        self.assertTrue(result["valid"])
        rendered=render_verified_answer(result,BUNDLE)
        self.assertIn('1101',rendered); self.assertNotIn('ignored',rendered)
    def test_route_facts_render_as_tables_without_model_text(self):
        bundle={"bundle_id":"bundle-routes","payload":{"facts":[
            {"fact_id":"groups","fact_kind":"route_groups","value":[{"table":"101","output_interface":"wg-h1-mpls","hub":"hub1","transport":"mpls","next_hop":None,"destinations":["10.2.0.0/24"]}]},
            {"fact_id":"rules","fact_kind":"routing_rules","value":[{"priority":2001,"fwmark":"0x1","fwmask":"0xff","table":"101","src":"all"}]}
        ],"unknowns":[],"limitations":[]}}
        answer={"answer_type":"operational","summary":"ignored","claims":[
            {"claim_id":"groups","claim_type":"routing_table","fact_ids":["groups"],"explanation":None},
            {"claim_id":"rules","claim_type":"routing_rule","fact_ids":["rules"],"explanation":None}
        ],"unknowns":[],"limitations":[]}
        result=self.validator.validate(answer,bundle)
        rendered=render_verified_answer(result,bundle)
        self.assertIn("| Table | Interface | Hub |", rendered)
        self.assertIn("| Priority | FWMark |", rendered)
        self.assertNotIn("ignored", rendered)

    def test_tunnel_claim_discards_tool_metadata_and_keeps_tunnel_fact(self):
        bundle={"bundle_id":"bundle-hub-tunnels","payload":{"facts":[
            {"fact_id":"hub","fact_kind":"hub","value":"hub2"},
            {"fact_id":"tunnels","fact_kind":"tunnels","value":{"availability":"AVAILABLE","value":"interface: wg-spokes-mpls"}}
        ],"unknowns":[],"limitations":[]}}
        answer={"answer_type":"operational","summary":"ignored","claims":[{"claim_id":"tunnels","claim_type":"tunnel_status","fact_ids":["hub","tunnels"],"explanation":None}],"unknowns":[],"limitations":[]}
        result=self.validator.validate(answer,bundle)
        self.assertTrue(result["valid"])
        self.assertEqual(result["answer"]["claims"][0]["fact_ids"], ["tunnels"])

    def test_tunnel_facts_render_as_observed_table_without_key_material(self):
        raw="""interface: wg-h1-mpls
  public key: public-value
  private key: (hidden)
  listening port: 52000

peer: peer-value
  endpoint: 192.168.10.1:52000
  allowed ips: 10.2.0.0/24
  latest handshake: 12 seconds ago
  transfer: 1 KiB received, 2 KiB sent
  persistent keepalive: every 10 seconds
"""
        bundle={"bundle_id":"bundle-tunnels","payload":{"facts":[{"fact_id":"tunnels","fact_kind":"tunnels","value":{"availability":"AVAILABLE","value":raw}}],"unknowns":[],"limitations":[]}}
        answer={"answer_type":"operational","summary":"ignored","claims":[{"claim_id":"tunnels","claim_type":"tunnel_status","fact_ids":["tunnels"],"explanation":None}],"unknowns":[],"limitations":[]}
        rendered=render_verified_answer(self.validator.validate(answer,bundle),bundle)
        self.assertIn("| Interface | Endpoint |", rendered)
        self.assertIn("wg-h1-mpls", rendered)
        self.assertNotIn("public-value", rendered)
        self.assertNotIn("private key", rendered)

    def test_single_endpoint_fact_renders_as_compact_table(self):
        bundle={"bundle_id":"bundle-endpoint","payload":{"facts":[{"fact_id":"endpoint","fact_kind":"endpoint","value":{"name":"node1_host","kind":"branch_host","ip":"10.1.0.10","site":"node1","aliases":["node1_host","node_host1"]}}],"unknowns":[],"limitations":[]}}
        answer={"answer_type":"operational","summary":"ignored","claims":[{"claim_id":"endpoint","claim_type":"endpoint","fact_ids":["endpoint"],"explanation":None}],"unknowns":[],"limitations":[]}
        rendered=render_verified_answer(self.validator.validate(answer,bundle),bundle)
        self.assertIn("Configured endpoint", rendered)
        self.assertIn("10.1.0.10", rendered)
        self.assertNotIn("ignored", rendered)

    def test_wireguard_hub_interface_renders_every_peer(self):
        raw="""interface: wg-spokes-mpls
peer: first-peer
  endpoint: 192.168.10.11:52128
  allowed ips: 10.1.0.0/24
  latest handshake: 5 seconds ago
  transfer: 1 KiB received, 2 KiB sent
  persistent keepalive: every 10 seconds
peer: second-peer
  endpoint: 192.168.10.12:52192
  allowed ips: 10.2.0.0/24
  latest handshake: 6 seconds ago
  transfer: 3 KiB received, 4 KiB sent
  persistent keepalive: every 10 seconds
"""
        bundle={"bundle_id":"bundle-hub-peers","payload":{"facts":[{"fact_id":"tunnels","fact_kind":"tunnels","value":{"availability":"AVAILABLE","value":raw}}],"unknowns":[],"limitations":[]}}
        answer={"answer_type":"operational","summary":"ignored","claims":[{"claim_id":"tunnels","claim_type":"tunnel_status","fact_ids":["tunnels"],"explanation":None}],"unknowns":[],"limitations":[]}
        rendered=render_verified_answer(self.validator.validate(answer,bundle),bundle)
        self.assertEqual(rendered.count("wg-spokes-mpls"), 2)
        self.assertIn("192.168.10.11:52128", rendered)
        self.assertIn("192.168.10.12:52192", rendered)

    def test_endpoint_route_facts_render_configured_and_observed_sections(self):
        bundle={"bundle_id":"bundle-path","payload":{"facts":[
            {"fact_id":"access","fact_kind":"host_access","value":{"source_host":"node1_host","source_ip":"10.1.0.10","edge_site":"node1","lan_gateway":"10.1.0.1","lan_network":"10.1.0.0/24"}},
            {"fact_id":"route","fact_kind":"edge_route","value":{"site":"node1","destination":"10.100.0.10","source":"10.1.0.10","packet_mark":None,"selected_routing_table":"1101","next_hop":None,"output_interface":"wg-h1-mpls","derived":{"hub":"hub1","transport":"mpls"}}}
        ],"unknowns":[],"limitations":[]}}
        answer={"answer_type":"operational","summary":"ignored","claims":[{"claim_id":"access","claim_type":"endpoint_route","fact_ids":["access","route"],"explanation":None}],"unknowns":[],"limitations":[]}
        rendered=render_verified_answer(self.validator.validate(answer,bundle),bundle)
        self.assertIn("Configured host access", rendered)
        self.assertIn("Observed edge route lookup", rendered)
        self.assertNotIn("ignored", rendered)

    def test_observed_mark_policy_renders_rule_and_candidate_separately(self):
        bundle={"bundle_id":"bundle-mark-policy","payload":{"facts":[{"fact_id":"policy","fact_kind":"observed_mark_policy","value":{"observed_mark":{"mark":4353},"matched_rule":{"table":1101,"fwmark":"0x1001"},"matching_route_candidates":[{"table":"1101","policy_rules":[{"fwmark":"0x1001"}],"output_interface":"wg-h1-mpls","hub":"hub1","transport":"mpls","matching_destinations":["10.100.0.0/24"]}]}}],"unknowns":[],"limitations":[]}}
        answer={"answer_type":"operational","summary":"ignored","claims":[{"claim_id":"flow","claim_type":"flow_route","fact_ids":["policy"],"explanation":None}],"unknowns":[],"limitations":[]}
        rendered=render_verified_answer(self.validator.validate(answer,bundle),bundle)
        self.assertIn("Observed-mark policy evidence", rendered)
        self.assertIn("Matching installed route candidates", rendered)
        self.assertIn("wg-h1-mpls", rendered)

    def test_endpoint_route_claim_is_completed_with_candidate_evidence(self):
        bundle={"bundle_id":"bundle-complete-path","payload":{"facts":[
            {"fact_id":"available","fact_kind":"available","value":True},
            {"fact_id":"source","fact_kind":"source","value":{"name":"node2_host"}},
            {"fact_id":"candidates","fact_kind":"policy_candidates","value":[]},
            {"fact_id":"limitations","fact_kind":"limitations","value":["example"]}
        ],"unknowns":[],"limitations":[]}}
        answer={"answer_type":"operational","summary":"ignored","claims":[{"claim_id":"path","claim_type":"endpoint_route","fact_ids":["available","source","candidates","limitations"],"explanation":None}],"unknowns":[],"limitations":[]}
        result=self.validator.validate(answer,bundle)
        self.assertTrue(result["valid"])
        self.assertEqual(result["answer"]["claims"][0]["fact_ids"], ["source", "candidates"])

    def test_policy_candidates_and_observed_flow_render_as_separate_evidence(self):
        bundle={"bundle_id":"bundle-candidates","payload":{"facts":[
            {"fact_id":"candidates","fact_kind":"policy_candidates","value":[{"table":"1101","policy_rules":[{"fwmark":"0x1001"}],"output_interface":"wg-h1-mpls","hub":"hub1","transport":"mpls","matching_destinations":["10.100.0.0/24"]}]},
            {"fact_id":"flow","fact_kind":"flow_observation","value":{"flow_count":1,"marks":[{"mark":4097,"raw_mark":"0x1001"}]}},
            {"fact_id":"live","fact_kind":"selected_live_route","value":{"packet_mark":4097,"selected_routing_table":1101,"output_interface":"wg-h1-mpls","derived":{"hub":"hub1","transport":"mpls"}}}
        ],"unknowns":[],"limitations":[]}}
        answer={"answer_type":"operational","summary":"ignored","claims":[{"claim_id":"candidates","claim_type":"endpoint_route","fact_ids":["candidates"],"explanation":None},{"claim_id":"flow","claim_type":"flow_route","fact_ids":["flow","live"],"explanation":None}],"unknowns":[],"limitations":[]}
        rendered=render_verified_answer(self.validator.validate(answer,bundle),bundle)
        self.assertIn("Matching policy-route candidates", rendered)
        self.assertIn("Route lookup using observed flow mark", rendered)
        self.assertNotIn("ignored", rendered)

    def test_endpoint_route_unavailable_lookup_is_rendered_without_a_route_claim(self):
        bundle={"bundle_id":"bundle-unavailable-path","payload":{"facts":[
            {"fact_id":"source","fact_kind":"source","value":{"name":"node1_host","kind":"branch_host","ip":"10.1.0.10","site":"node1"}},
            {"fact_id":"destination","fact_kind":"destination","value":{"name":"dc_app","kind":"data_center_application","ip":"10.100.0.10"}},
            {"fact_id":"access","fact_kind":"host_access","value":{"source_host":"node1_host","source_ip":"10.1.0.10","edge_site":"node1","lan_gateway":"10.1.0.1","lan_network":"10.1.0.0/24"}},
            {"fact_id":"route","fact_kind":"edge_route","value":{"available":False,"reason":"RTNETLINK answers: Network is unreachable"}}
        ],"unknowns":[],"limitations":[]}}
        answer={"answer_type":"operational","summary":"ignored","claims":[{"claim_id":"path","claim_type":"endpoint_route","fact_ids":["source","destination","access","route"],"explanation":None}],"unknowns":[],"limitations":[]}
        result=self.validator.validate(answer,bundle)
        self.assertTrue(result["valid"])
        rendered=render_verified_answer(result,bundle)
        self.assertIn("Resolved source endpoint", rendered)
        self.assertIn("Lookup availability", rendered)
        self.assertIn("RTNETLINK answers: Network is unreachable", rendered)
        self.assertNotIn("ignored", rendered)

    def test_unknown_fact_and_wrong_kind_are_rejected(self):
        unknown={"answer_type":"operational","summary":"x","claims":[{"claim_id":"c","claim_type":"route","fact_ids":["missing"],"explanation":None}],"unknowns":[],"limitations":[]}
        self.assertFalse(self.validator.validate(unknown,BUNDLE)["valid"])
        wrong={"answer_type":"operational","summary":"x","claims":[{"claim_id":"c","claim_type":"route","fact_ids":["f-interface"],"explanation":None}],"unknowns":[],"limitations":[]}
        self.assertFalse(self.validator.validate(wrong,BUNDLE)["valid"])
    def test_operational_answer_without_evidence_is_rejected(self):
        answer={"answer_type":"operational","summary":"x","claims":[],"unknowns":[],"limitations":[]}
        result=self.validator.validate(answer,{"payload":{"facts":[]}})
        self.assertFalse(result["valid"])
        self.assertIn("NO_MCP_EVIDENCE",[item["code"] for item in result["errors"]])
