"""In-process fixture regressions: no listening socket, TLS files or host state."""
import base64
import hashlib
import hmac
import io
import json
import runpy
import secrets
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

FIXTURE = Path(__file__).with_name('mock-control-plane.py')
CONCRETE_PATH = type(FIXTURE)
VERSION = json.loads(FIXTURE.parents[2].joinpath('agent/package.json').read_text())['version']


class ControlPlaneTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pluton-control-plane-test-')
        self.addCleanup(temporary.cleanup)
        private = Path(temporary.name)
        private.chmod(0o700)
        self.token = secrets.token_urlsafe(32)
        private.joinpath('token').write_text(self.token)
        # Substitute only the private fixture directory. Load and exercise the
        # actual handler; no change to its token, version or signature checks.
        def fixture_path(value):
            return private if value == '/tmp/pluton-install-private' else CONCRETE_PATH(value)
        with patch.object(sys, 'argv', [str(FIXTURE)]), \
             patch('pathlib.Path', side_effect=fixture_path), \
             patch('http.server.HTTPServer'), patch('ssl.SSLContext'):
            self.fixture = runpy.run_path(str(FIXTURE))

    def request(self, route, body, headers=None):
        raw = json.dumps(body).encode()
        handler = object.__new__(self.fixture['Handler'])
        handler.path = route
        handler.headers = {'Content-Length': str(len(raw)), **(headers or {})}
        handler.rfile = io.BytesIO(raw)
        handler.wfile = io.BytesIO()
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.do_POST()
        status = handler.send_response.call_args.args[0]
        if status == 401:
            self.assertEqual(handler.wfile.getvalue(), b'{"success":false,"error":"Synthetic request rejected"}')
        return status

    def inventory(self, version=VERSION, capability=1):
        return {'agentVersion': version, 'capabilities': {'backupExclusionsVersion': capability}}

    def enroll(self, token=None, inventory=None):
        return self.request('/api/agent/enroll', {
            'token': self.token if token is None else token,
            'inventory': self.inventory() if inventory is None else inventory,
        })

    def signed_headers(self, body, secret=None, stamp=None, agent_id='synthetic-agent'):
        stamp = str(int(time.time() * 1000)) if stamp is None else stamp
        nonce = secrets.token_hex(16)
        digest = base64.urlsafe_b64encode(hashlib.sha256(json.dumps(body).encode()).digest()).decode().rstrip('=')
        canonical = '\n'.join([stamp, nonce, 'POST', '/api/agent/heartbeat', digest])
        secret = self.fixture['secret'] if secret is None else secret
        signature = base64.b64encode(hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).digest()).decode()
        return {'x-pluton-agent-id': agent_id, 'x-pluton-agent-timestamp': stamp,
                'x-pluton-agent-nonce': nonce, 'x-pluton-agent-signature': signature}

    def test_current_release_enrollment_and_signed_heartbeat(self):
        self.assertEqual(self.enroll(), 200)
        body = self.inventory()
        self.assertEqual(self.request('/api/agent/heartbeat', body, self.signed_headers(body)), 200)
        self.assertEqual(self.fixture['proof'], {'enrollments': 1, 'heartbeats': 1, 'polls': 0})

    def test_invalid_enrollment_does_not_consume_success(self):
        for token, inventory in [(self.token + '-invalid', self.inventory()),
                                 (self.token, self.inventory('0.0.0')),
                                 (self.token, self.inventory(capability=0))]:
            self.assertEqual(self.enroll(token, inventory), 401)
            self.assertEqual(self.fixture['proof']['enrollments'], 0)
        self.assertEqual(self.enroll(), 200)
        self.assertEqual(self.enroll(), 401)  # One-time enrollment remains strict.

    def test_heartbeat_authentication_and_inventory_remain_strict(self):
        self.assertEqual(self.enroll(), 200)
        body = self.inventory()
        for headers in [{}, self.signed_headers(body, secret='synthetic-wrong-secret'),
                        self.signed_headers(body, stamp='0'),
                        self.signed_headers(body, agent_id='synthetic-other-agent')]:
            self.assertEqual(self.request('/api/agent/heartbeat', body, headers), 401)
        for invalid in [self.inventory('0.0.0'), self.inventory(capability=0)]:
            self.assertEqual(self.request('/api/agent/heartbeat', invalid, self.signed_headers(invalid)), 401)
        self.assertEqual(self.fixture['proof']['heartbeats'], 0)
        headers = self.signed_headers(body)
        self.assertEqual(self.request('/api/agent/heartbeat', body, headers), 200)
        self.assertEqual(self.request('/api/agent/heartbeat', body, headers), 401)
        self.assertEqual(self.fixture['proof']['heartbeats'], 1)


if __name__ == '__main__':
    unittest.main()
