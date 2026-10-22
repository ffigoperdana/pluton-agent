"""Exercise the real curl binary against disposable loopback TLS only."""
import http.server
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading

helper = Path(__file__).resolve().parents[1] / "lib/dependency-download.sh"
payload = b"synthetic-complete-verified-download"
requests = []
behavior = "partial"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        requests.append((self.command, self.path, self.headers.get("Authorization")))
        if behavior == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/forbidden")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif behavior == "partial" and len(requests) == 1:
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload) + 10))
            self.end_headers()
            self.wfile.write(b"interrupted-prefix")
            self.wfile.flush()
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
        else:
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    def log_message(self, *_args):
        pass


with tempfile.TemporaryDirectory(prefix="pluton-dependency-tls-") as temporary:
    root = Path(temporary)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                    "-keyout", str(root / "key.pem"), "-out", str(root / "ca.pem")],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / "ca.pem", root / "key.pem")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # These are fixture constants, never production environment overrides.
    script = '''source "$1"
NODE_VERSION=v22.23.4
RESTIC_VERSION=0.19.1
RCLONE_VERSION=1.75.1
NODE_DIST_BASE="$2"
RESTIC_RELEASE_BASE="$2"
RCLONE_RELEASE_BASE="$2"
log() { printf '%s\\n' "$*"; }
download_dependency restic "$3"
'''
    # A user curlrc must not inject POST, credentials or insecure TLS.
    (root / ".curlrc").write_text('insecure\nrequest = "POST"\nheader = "Authorization: synthetic-private-token"\n')
    environment = {key: value for key, value in os.environ.items()
                   if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "curl_ca_bundle",
                                          "ssl_cert_file", "ssl_cert_dir", "curl_home", "xdg_config_home"}}
    environment.update(HOME=str(root), CURL_HOME=str(root), NO_PROXY="*", CURL_CA_BUNDLE=str(root / "ca.pem"))

    def run(host="localhost", trusted=True):
        destination = root / "artifact"
        destination.unlink(missing_ok=True)
        current_env = environment.copy()
        if not trusted:
            current_env.pop("CURL_CA_BUNDLE")
        result = subprocess.run(["bash", "-Eeuo", "pipefail", "-c", script, "fixture", str(helper),
                                 f"https://{host}:{server.server_port}", str(destination)],
                                env=current_env, text=True, capture_output=True, timeout=20)
        assert "synthetic-private-token" not in result.stdout + result.stderr
        assert not (root / "artifact.part").exists()
        return result, destination

    try:
        result, destination = run()
        assert result.returncode == 0, result.stdout
        assert destination.read_bytes() == payload
        assert len(requests) == 2 and all(method == "GET" and auth is None for method, _, auth in requests)
        print("PASS real HTTPS interrupted GET retries from zero; curlrc cannot inject POST/auth/insecure TLS")
        behavior = "healthy"
        for host, trusted in [("localhost", False), ("127.0.0.1", True)]:
            requests.clear()
            result, destination = run(host, trusted)
            assert result.returncode != 0 and not destination.exists() and not requests
            assert "attempt 1/4: TLS verification or configuration failed" in result.stdout
            assert "retrying" not in result.stdout
        print("PASS real curl rejects untrusted CA and wrong hostname without retry or GET")
        behavior = "redirect"
        requests.clear()
        result, destination = run()
        assert result.returncode != 0 and not destination.exists() and len(requests) == 1, (
            f"exit={result.returncode}, GETs={len(requests)}; {result.stdout}")
        assert "retrying" not in result.stdout
        print("PASS HTTPS redirect cannot downgrade to HTTP")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
