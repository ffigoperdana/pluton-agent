"""Disposable TLS/HMAC enrollment fixture. No live server, token or inventory."""
import base64
import hashlib
import hmac
import http.server
import json
import secrets
import ssl
import time
from pathlib import Path

private = Path('/tmp/pluton-install-private')
secret = secrets.token_hex(32)
token = private.joinpath('token').read_text().strip()
proof = {'enrollments': 0, 'heartbeats': 0, 'polls': 0}
nonces = set()

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        try:
            body = json.loads(raw)
            if self.path == '/api/agent/enroll':
                assert hmac.compare_digest(body['token'], token)
                assert proof['enrollments'] == 0
                assert body['inventory']['agentVersion'] == '0.7.0'
                assert body['inventory']['capabilities']['backupExclusionsVersion'] == 1
                proof['enrollments'] += 1
                result = dict(deviceId='synthetic-device', agentId='synthetic-agent', secret=secret, pollIntervalSeconds=15)
            else:
                assert self.path == '/api/agent/heartbeat'  # Never lease work to prove health.
                stamp = self.headers['x-pluton-agent-timestamp']
                nonce = self.headers['x-pluton-agent-nonce']
                assert self.headers['x-pluton-agent-id'] == 'synthetic-agent'
                assert abs(time.time()*1000 - int(stamp)) < 60000 and nonce not in nonces
                digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')
                canonical = '\n'.join([stamp, nonce, 'POST', self.path, digest])
                signature = base64.b64encode(hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).digest()).decode()
                assert hmac.compare_digest(signature, self.headers['x-pluton-agent-signature'])
                nonces.add(nonce)
                assert body['agentVersion'] == '0.7.0' and body['capabilities']['backupExclusionsVersion'] == 1
                proof['heartbeats'] += 1
                result = {}
            private.joinpath('proof.json').write_text(json.dumps(proof))
            response = json.dumps({'success': True, 'result': result}).encode()
            self.send_response(200)
        except Exception:
            response = b'{"success":false,"error":"Synthetic request rejected"}'
            self.send_response(401)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)

server = http.server.HTTPServer(('127.0.0.1', 18443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(private / 'cert.pem', private / 'key.pem')
server.socket = context.wrap_socket(server.socket, server_side=True)
private.joinpath('ready').touch()
server.serve_forever()
