from __future__ import annotations
import tempfile
from pathlib import Path
import unittest
from fastapi.testclient import TestClient
from sdwan.management.app import create_app
from sdwan.management.config import ManagementConfig
from sdwan.management.service import ManagementService
ROOT = Path(__file__).resolve().parents[1]
class ManagementTests(unittest.TestCase):
    def app(self, directory):
        return TestClient(create_app(ManagementConfig(ROOT/'config/topology.yaml', Path(directory)/'policy.db', Path(directory)/'ztp.db', Path(directory), 'test-secret', 'viewer:pw:VIEWER,admin:pw:ADMIN', '')))
    def token(self, client, user):
        return client.post('/api/v1/auth/login', json={'username':user,'password':'pw'}).json()['access_token']
    def test_viewer_reads_health_but_not_routes(self):
        with tempfile.TemporaryDirectory() as directory:
            client=self.app(directory); headers={'Authorization':'Bearer '+self.token(client,'viewer')}
            health=client.get('/api/v1/system/health',headers=headers); self.assertEqual(health.status_code,200); self.assertIn('X-Request-ID',health.headers)
            self.assertEqual(client.get('/api/v1/audit',headers=headers).status_code,403)
    def test_underlay_endpoint_is_read_only_and_handles_a_missing_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            client = self.app(directory)
            headers = {'Authorization':'Bearer ' + self.token(client, 'viewer')}
            response = client.get('/api/v1/underlay/state', headers=headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()['availability'], 'UNAVAILABLE')

    def test_path_and_workload_endpoints_are_available_to_viewers(self):
        with tempfile.TemporaryDirectory() as directory:
            client = self.app(directory)
            headers = {'Authorization':'Bearer ' + self.token(client, 'viewer')}
            paths = client.get('/api/v1/paths', headers=headers)
            self.assertEqual(paths.status_code, 200)
            self.assertIn('measurement', paths.json())
            for endpoint in ('/api/v1/path-metrics', '/api/v1/path-decisions', '/api/v1/path-events'):
                response = client.get(endpoint, headers=headers)
                self.assertEqual(response.status_code, 200)
                self.assertIsInstance(response.json(), list)
            workloads = client.get('/api/v1/workloads', headers=headers)
            self.assertEqual(workloads.status_code, 200)
            by_id = {item['id']: item for item in workloads.json()}
            self.assertEqual(set(by_id), {'branch_rtp', 'central_backup', 'public_saas'})
            self.assertEqual(by_id['public_saas']['egress'], 'DIRECT_INTERNET')

    def test_core_profile_hides_cloud_runtime_and_exposes_one_public_saas(self):
        with tempfile.TemporaryDirectory() as directory:
            client = self.app(directory)
            headers = {'Authorization':'Bearer ' + self.token(client, 'viewer')}
            gateways = client.get('/api/v1/cloud-vpc/gateways', headers=headers).json()
            self.assertTrue(gateways)
            self.assertTrue(all(item['availability'] == 'DISABLED' for item in gateways))
            destinations = client.get('/api/v1/saas/destinations', headers=headers).json()
            self.assertEqual(len(destinations), 1)
            self.assertEqual(destinations[0]['name'], 'public_saas')
            self.assertEqual(destinations[0]['candidate_transports'], ['bb', 'lte'])

    def test_platform_admin_chat_is_persisted_and_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            client=self.app(directory); headers={'Authorization':'Bearer '+self.token(client,'admin')}
            session=client.post('/api/v1/chat/sessions',headers=headers).json()['session_id']
            from unittest.mock import patch
            async def fake_run(*args, **kwargs):
                from sdwan.management.agent import AgentEvent
                yield AgentEvent('assistant_delta', {'text':'read-only status'})
                yield AgentEvent('agent_completed', {})
            with patch('sdwan.management.app.OllamaClaudeRunner.run', fake_run):
                response=client.post('/api/v1/chat/sessions/%s/messages'%session,headers=headers,json={'message':'status'})
            self.assertEqual(response.status_code,202); self.assertTrue(response.json()['accepted'])
            self.assertEqual(len(client.get('/api/v1/chat/sessions/%s'%session,headers=headers).json()),2)
            self.assertTrue(client.get('/api/v1/audit',headers=headers).json())
    def test_chat_retries_once_when_agent_produces_no_final_result(self):
        with tempfile.TemporaryDirectory() as directory:
            client=self.app(directory); headers={'Authorization':'Bearer '+self.token(client,'admin')}
            session=client.post('/api/v1/chat/sessions',headers=headers).json()['session_id']
            from unittest.mock import patch
            calls=[]
            async def fake_run(*args, **kwargs):
                calls.append(1)
                from sdwan.management.agent import AgentEvent
                if len(calls) == 1:
                    yield AgentEvent('agent_completed', {})
                else:
                    yield AgentEvent('agent_final', {'text':'{"answer_type":"operational","summary":"x","claims":[],"unknowns":[],"limitations":[]}'})
                    yield AgentEvent('agent_completed', {})
            with patch('sdwan.management.app.OllamaClaudeRunner.run', fake_run):
                response=client.post('/api/v1/chat/sessions/%s/messages'%session,headers=headers,json={'message':'status'})
            self.assertEqual(response.status_code,202)
            self.assertEqual(len(calls), 2)

    def test_route_decision_report_is_deterministic_and_evidence_bounded(self):
        class Runtime:
            def routes(self, site):
                return {"availability":"AVAILABLE","value":[
                    {"dst":"10.2.0.0/24","table":1101,"dev":"wg-h1-mpls"},
                    {"dst":"198.18.0.10","table":102,"dev":"node1-bb","gateway":"192.168.20.254"},
                    {"dst":"fe80::/64","table":1101,"dev":"wg-h1-mpls"},
                ]}
            def route_lookup(self, site, destination, source=None, fwmark=None):
                return {"availability":"AVAILABLE","value":[{"dst":destination,"table":1101,"dev":"wg-h1-mpls"}]}
            def rules(self, site):
                return {"availability":"AVAILABLE","value":[
                    {"priority":1101,"fwmark":"0x1001","fwmask":"0x30ff","table":1101},
                    {"priority":2002,"fwmark":"0x2","fwmask":"0xff","table":102},
                ]}
        with tempfile.TemporaryDirectory() as directory:
            config = ManagementConfig(ROOT/'config/topology.yaml', Path(directory)/'policy.db', Path(directory)/'ztp.db', Path(directory), 'test-secret', '', '')
            service = ManagementService(config); service.runtime = Runtime()
            report = service.route_decision_report('node1', '10.2.0.10', fwmark=0x1001)
        self.assertTrue(report['available'])
        self.assertEqual(report['selected_routing_table'], 1101)
        self.assertEqual(report['matched_rule']['table'], 1101)
        self.assertEqual(report['output_interface'], 'wg-h1-mpls')
        self.assertEqual(report['derived']['hub'], 'hub1')
        self.assertIn('connection_mark', [item['field'] for item in report['unknowns']])

    def test_site_status_is_compact_configured_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            config = ManagementConfig(ROOT/'config/topology.yaml', Path(directory)/'policy.db', Path(directory)/'ztp.db', Path(directory), 'test-secret', '', '')
            service = ManagementService(config)
            status = service.site_status('node1')
        self.assertEqual(status['site'], 'node1')
        self.assertEqual(status['lan_prefix'], '10.1.0.0/24')
        self.assertEqual(status['preferred_hub'], 'hub1')
        self.assertNotIn('routes', status)
        self.assertNotIn('tunnels', status)

    def test_cloud_gateway_configuration_is_not_a_site_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            config = ManagementConfig(ROOT/'config/topology.yaml', Path(directory)/'policy.db', Path(directory)/'ztp.db', Path(directory), 'test-secret', '', '')
            gateway = ManagementService(config).cloud_gateway('cloud_gw1')
        self.assertTrue(gateway['available'])
        self.assertEqual(gateway['gateway'], 'cloud_gw1')
        self.assertEqual(gateway['vpc_ip'], '10.200.0.1')
        self.assertEqual(gateway['management_ip'], '172.30.0.21')
        self.assertEqual(len(gateway['transits']), 2)

    def test_hub_tunnels_use_the_hub_runtime_namespace(self):
        class Runtime:
            def tunnels(self, hub): return {"availability":"AVAILABLE","value":"interface: wg-spokes-mpls"}
        with tempfile.TemporaryDirectory() as directory:
            config = ManagementConfig(ROOT/'config/topology.yaml', Path(directory)/'policy.db', Path(directory)/'ztp.db', Path(directory), 'test-secret', '', '')
            service=ManagementService(config); service.runtime=Runtime()
            report=service.hub_tunnels('hub2')
        self.assertEqual(report['hub'], 'hub2')
        self.assertEqual(report['tunnels']['value'], 'interface: wg-spokes-mpls')

    def test_site_host_route_never_resolves_to_the_edge(self):
        class Runtime:
            def route_lookup(self, site, destination, source=None, fwmark=None): return {"availability":"AVAILABLE","value":[]}
            def routes(self, site): return {"availability":"AVAILABLE","value":[]}
            def rules(self, site): return {"availability":"AVAILABLE","value":[]}
        with tempfile.TemporaryDirectory() as directory:
            config = ManagementConfig(ROOT/'config/topology.yaml', Path(directory)/'policy.db', Path(directory)/'ztp.db', Path(directory), 'test-secret', '', '')
            service=ManagementService(config); service.runtime=Runtime()
            report=service.site_host_route('node2','data_center')
        self.assertEqual(report['source']['name'], 'node2_host')
        self.assertEqual(report['source']['ip'], '10.2.0.10')
        self.assertEqual(report['host_access']['lan_gateway'], '10.2.0.1')

    def test_policy_candidates_are_not_reported_as_a_selected_route(self):
        class Runtime:
            def routes(self, site): return {"availability":"AVAILABLE","value":[{"dst":"10.100.0.0/24","table":1101,"dev":"wg-h1-mpls"}]}
            def rules(self, site): return {"availability":"AVAILABLE","value":[{"priority":1101,"fwmark":"0x1001","fwmask":"0x30ff","table":1101}]}
            def route_lookup(self, site, destination, source=None, fwmark=None): return {"availability":"AVAILABLE","value":[]}
        with tempfile.TemporaryDirectory() as directory:
            config = ManagementConfig(ROOT/'config/topology.yaml', Path(directory)/'policy.db', Path(directory)/'ztp.db', Path(directory), 'test-secret', '', '')
            service=ManagementService(config); service.runtime=Runtime()
            report=service.endpoint_route('node_host2','dc')
        self.assertEqual(report['policy_candidates'][0]['table'], '1101')
        self.assertIsNone(report['edge_route']['selected_routing_table'])

    def test_observed_flow_uses_only_an_existing_conntrack_mark(self):
        class Runtime:
            def connection_marks(self, site, source, destination): return {"availability":"AVAILABLE","value":[{"mark":4097,"raw_mark":"0x1001"}]}
            def route_lookup(self, site, destination, source=None, fwmark=None): return {"availability":"AVAILABLE","value":[{"dst":destination,"table":1101,"dev":"wg-h1-mpls"}]}
            def rules(self, site): return {"availability":"AVAILABLE","value":[{"priority":1101,"fwmark":"0x1001","fwmask":"0x30ff","table":1101}]}
        with tempfile.TemporaryDirectory() as directory:
            config = ManagementConfig(ROOT/'config/topology.yaml', Path(directory)/'policy.db', Path(directory)/'ztp.db', Path(directory), 'test-secret', '', '')
            service=ManagementService(config); service.runtime=Runtime()
            report=service.observe_endpoint_flow('node_host2','dc')
        self.assertEqual(report['flow_observation']['marks'][0]['mark'], 4097)
        self.assertEqual(report['selected_live_route']['output_interface'], 'wg-h1-mpls')

    def test_observed_mark_policy_survives_an_unavailable_marked_lookup(self):
        class Runtime:
            def connection_marks(self, site, source, destination): return {"availability":"AVAILABLE","value":[{"mark":4353,"raw_mark":"4353"}]}
            def route_lookup(self, site, destination, source=None, fwmark=None): return {"availability":"UNAVAILABLE","reason":"RTNETLINK answers: Network is unreachable"}
            def routes(self, site): return {"availability":"AVAILABLE","value":[{"dst":"10.100.0.0/24","table":1101,"dev":"wg-h1-mpls"}]}
            def rules(self, site): return {"availability":"AVAILABLE","value":[{"priority":1101,"fwmark":"0x1001","fwmask":"0x30ff","table":1101}]}
        with tempfile.TemporaryDirectory() as directory:
            config = ManagementConfig(ROOT/'config/topology.yaml', Path(directory)/'policy.db', Path(directory)/'ztp.db', Path(directory), 'test-secret', '', '')
            service=ManagementService(config); service.runtime=Runtime()
            report=service.observe_endpoint_flow('node2_host','dc')
        self.assertFalse(report['selected_live_route']['available'])
        self.assertEqual(report['selected_live_route']['matched_rule']['table'], 1101)
        self.assertEqual(report['observed_mark_policy']['matching_route_candidates'][0]['table'], '1101')

    def test_observed_mark_policy_is_reported_when_lookup_has_no_route_record(self):
        class Runtime:
            def connection_marks(self, site, source, destination): return {"availability":"AVAILABLE","value":[{"mark":4353,"raw_mark":"4353"}]}
            def route_lookup(self, site, destination, source=None, fwmark=None): return {"availability":"AVAILABLE","value":[]}
            def routes(self, site): return {"availability":"AVAILABLE","value":[{"dst":"10.100.0.0/24","table":1101,"dev":"wg-h1-mpls"}]}
            def rules(self, site): return {"availability":"AVAILABLE","value":[{"priority":1101,"fwmark":"0x1001","fwmask":"0x30ff","table":1101}]}
        with tempfile.TemporaryDirectory() as directory:
            config = ManagementConfig(ROOT/'config/topology.yaml', Path(directory)/'policy.db', Path(directory)/'ztp.db', Path(directory), 'test-secret', '', '')
            service=ManagementService(config); service.runtime=Runtime()
            report=service.observe_endpoint_flow('node2_host','dc')
        self.assertEqual(report['selected_live_route']['lookup_status'], 'no route record returned')
        self.assertEqual(report['observed_mark_policy']['matched_rule']['table'], 1101)
        self.assertEqual(report['observed_mark_policy']['matching_route_candidates'][0]['output_interface'], 'wg-h1-mpls')

    def test_endpoint_resolves_a_single_host_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            config = ManagementConfig(ROOT/'config/topology.yaml', Path(directory)/'policy.db', Path(directory)/'ztp.db', Path(directory), 'test-secret', '', '')
            result = ManagementService(config).endpoint('node_host1')
        self.assertTrue(result['available'])
        self.assertEqual(result['endpoint']['name'], 'node1_host')
        self.assertEqual(result['endpoint']['ip'], '10.1.0.10')

    def test_endpoint_route_resolves_host_and_data_center_aliases(self):
        class Runtime:
            def route_lookup(self, site, destination, source=None, fwmark=None):
                return {"availability":"AVAILABLE","value":[{"dst":destination,"table":1101,"dev":"wg-h1-mpls"}]}
            def rules(self, site): return {"availability":"AVAILABLE","value":[]}
        with tempfile.TemporaryDirectory() as directory:
            config = ManagementConfig(ROOT/'config/topology.yaml', Path(directory)/'policy.db', Path(directory)/'ztp.db', Path(directory), 'test-secret', '', '')
            service = ManagementService(config); service.runtime = Runtime()
            report = service.endpoint_route('node_host1', 'data center')
        self.assertTrue(report['available'])
        self.assertEqual(report['source']['name'], 'node1_host')
        self.assertEqual(report['destination']['ip'], '10.100.0.10')
        self.assertEqual(report['host_access']['lan_gateway'], '10.1.0.1')
        self.assertEqual(report['edge_route']['output_interface'], 'wg-h1-mpls')

    def test_no_http_mcp_endpoint_and_session_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            client=self.app(directory); viewer={'Authorization':'Bearer '+self.token(client,'viewer')}; admin={'Authorization':'Bearer '+self.token(client,'admin')}
            self.assertEqual(client.post('/mcp',json={'method':'initialize','id':1}).status_code,404)
            session=client.post('/api/v1/chat/sessions',headers=viewer).json()['session_id']
            self.assertEqual(client.get('/api/v1/chat/sessions/%s'%session,headers=admin).status_code,404)
            self.assertEqual(client.get('/api/v1/dashboard/summary',headers=viewer).status_code,200)

class ManagementLifecycleApiTests(unittest.TestCase):
    def test_site_create_uses_canonical_endpoint_and_fails_closed_without_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            config = ManagementConfig(ROOT/'config/topology.yaml', Path(directory)/'policy.db', Path(directory)/'ztp.db', Path(directory), 'test-secret', 'admin:pw:ADMIN', '')
            client = TestClient(create_app(config))
            token = client.post('/api/v1/auth/login', json={'username':'admin','password':'pw'}).json()['access_token']
            response = client.post('/api/v1/sites', headers={'Authorization':'Bearer '+token}, json={'site_id':'node6','role':'spoke'})
            self.assertEqual(response.status_code, 202)
            payload = response.json()
            self.assertEqual(payload['site_id'], 'node6')
            self.assertEqual(payload['state'], 'FAILED')
            self.assertEqual(payload['failure_stage'], 'TOPOLOGY_CREATED')
            self.assertNotIn('claim_secret', str(payload))
            operation = client.get('/api/v1/operations/'+payload['operation_id'], headers={'Authorization':'Bearer '+token})
            self.assertEqual(operation.status_code, 200)
            self.assertEqual(operation.json()['state'], 'FAILED')
            self.assertEqual(client.post('/api/v1/admin/sites', headers={'Authorization':'Bearer '+token}, json={'site':'node7'}).status_code, 404)
