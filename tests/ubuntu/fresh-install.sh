#!/usr/bin/env bash
set -Eeuo pipefail
[[ -f /opt/pluton-disposable-ubuntu-test && ${PLUTON_DISPOSABLE_INSTALL_TEST:-} == 1 && $EUID == 0 ]] || exit 90
[[ ! -e /opt/pluton-agent && ! -e /var/lib/pluton-agent/identity.json ]] || exit 91
[[ ! -e /workspace/backend && ! -e /workspace/frontend && ! -e /workspace/.git ]] || exit 92
if command -v node >/dev/null 2>&1; then printf 'Fresh host fixture unexpectedly has global Node\n' >&2; exit 94; fi
. /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == "$UBUNTU_VERSION" && "$(uname -m)" == x86_64 ]]
printf 'VALIDATION OS: %s; kernel shared with Docker, not a native Ubuntu boot\n' "$PRETTY_NAME"
/usr/bin/systemctl --version
# Drain the producer: head can close early and make pipefail report SIGPIPE (141).
ldd --version | sed -n '1p'
python3 --version
mkdir -p /tmp/pluton-install-private /opt/test-trust /srv/example-app /run/systemd/system
chmod 0700 /tmp/pluton-install-private
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost' -keyout /tmp/pluton-install-private/key.pem \
  -out /tmp/pluton-install-private/cert.pem >/dev/null 2>&1
cp /tmp/pluton-install-private/cert.pem /opt/test-trust/ca.pem
chmod 0644 /opt/test-trust/ca.pem
# Public preflight runs without privilege, credentials, network or installation.
runuser -u nobody -- bash install-agent.sh --check --server https://localhost:18443 \
  --allowed-root /srv/example-app --ca-file /opt/test-trust/ca.pem
[[ ! -e /opt/pluton-agent && ! -e /etc/pluton-agent.env && ! -e /var/lib/pluton-agent/identity.json && ! -e /etc/systemd/system/pluton-agent.service ]]
python3 -c 'import secrets;print(secrets.token_urlsafe(32))' > /tmp/pluton-install-private/token
python3 tests/ubuntu/mock-control-plane.py &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true' EXIT
for attempt in {1..50}; do [[ ! -f /tmp/pluton-install-private/ready ]] || break; sleep 0.1; done
[[ -f /tmp/pluton-install-private/ready ]]
# Real private downloads, SHA checks, dependency install/build, root ownership,
# enrollment, TLS and signed heartbeat. Only systemd is explicitly adapted.
bash install-agent.sh --server https://localhost:18443 --allowed-root /srv/example-app \
  --ca-file /opt/test-trust/ca.pem --token-stdin < /tmp/pluton-install-private/token
node=/opt/pluton-agent/runtime/bin/node
expected_node="${PLUTON_EXPECT_NODE_VERSION:-v22.23.4}"
[[ "$expected_node" == v22.23.4 || "$expected_node" == v22.18.0 ]]
[[ "$($node -v)" == "$expected_node" ]]
/opt/pluton-agent/bin/restic version | grep -F '0.19.1'
/opt/pluton-agent/bin/rclone version | sed -n '1p' | grep -F '1.75.1'
grep -Fx 'distribution=pluton-agent-standalone-v1' /opt/pluton-agent/.verified-install >/dev/null
grep -Fx 'User=pluton-agent' /etc/systemd/system/pluton-agent.service >/dev/null
/usr/bin/systemd-analyze verify /etc/systemd/system/pluton-agent.service
[[ "$(stat -c '%u:%a' /etc/pluton-agent.env)" == 0:600 ]]
[[ "$(stat -c '%a' /var/lib/pluton-agent/identity.json)" == 600 ]]
[[ "$(stat -c '%U:%a' /var/lib/pluton-agent)" == pluton-agent:700 ]]
[[ "$(getent passwd pluton-agent | cut -d: -f7)" == /usr/sbin/nologin ]]
! runuser -u pluton-agent -- test -r /etc/pluton-agent.env
! runuser -u pluton-agent -- test -w /opt/pluton-agent/app/dist/index.js
# Ubuntu 24.04 images can already own UID 1000; never assume that UID is free.
# Test narrow ACL read/traversal and canonical aliases independently of policy.
mkdir -p /srv/acl-fixture/allowed
printf 'synthetic ACL data\n' > /srv/acl-fixture/allowed/sample
chmod 0700 /srv/acl-fixture /srv/acl-fixture/allowed
! runuser -u pluton-agent -- test -r /srv/acl-fixture/allowed/sample
setfacl -m u:pluton-agent:--x /srv/acl-fixture
setfacl -m u:pluton-agent:r-x /srv/acl-fixture/allowed
setfacl -m u:pluton-agent:r-- /srv/acl-fixture/allowed/sample
runuser -u pluton-agent -- cat /srv/acl-fixture/allowed/sample >/dev/null
! runuser -u pluton-agent -- test -w /srv/acl-fixture/allowed/sample
ln -s /srv/acl-fixture/allowed /srv/acl-alias
[[ "$(realpath -e /srv/acl-alias)" == /srv/acl-fixture/allowed ]]
# Neither untrusted CA nor a trusted certificate for the wrong hostname may pass.
for origin in https://localhost:18443 https://127.0.0.1:18443; do
  ca_args=()
  [[ "$origin" != https://127.0.0.1:18443 ]] || ca_args=(--ca-file /opt/test-trust/ca.pem)
  if runuser -u pluton-agent -- "$node" /opt/pluton-agent/app/dist/index.js check \
    --server "$origin" --data-dir /var/lib/pluton-agent --bin-dir /opt/pluton-agent/bin \
    --allowed-roots /srv/example-app "${ca_args[@]}" > /tmp/tls-rejection-result 2>&1; then
    printf 'TLS validation unexpectedly succeeded\n' >&2; exit 96
  fi
done
before=$(sha256sum /etc/pluton-agent.env /var/lib/pluton-agent/identity.json)
if bash install-agent.sh --server https://localhost:18443 --allowed-root /srv/example-app > /tmp/reinstall-result 2>&1; then exit 93; fi
grep -F 'Fresh standalone installation only' /tmp/reinstall-result >/dev/null
[[ "$before" == "$(sha256sum /etc/pluton-agent.env /var/lib/pluton-agent/identity.json)" ]]
# A monorepo-format record is NOT automatically adopted. Only this disposable
# fixture's additive marker is removed and its exact original is restored.
cp /opt/pluton-agent/.verified-install /tmp/pluton-install-private/provenance-original
sed -i '/^distribution=/d' /opt/pluton-agent/.verified-install
if bash upgrade-agent.sh --check > /tmp/legacy-refusal-result 2>&1; then exit 95; fi
grep -F 'monorepo installations require separate state-preserving migration approval' /tmp/legacy-refusal-result >/dev/null
"$node" - <<'NODE'
const assert = require('node:assert/strict');
const { productionContext } = require('./installers/lib/upgrade-agent.cjs');
assert.throws(() => productionContext(process.cwd()), /monorepo migration requires separate review/);
NODE
if "$node" installers/lib/upgrade-agent.cjs "$PWD" --check > /tmp/legacy-direct-refusal-result 2>&1; then exit 95; fi
grep -Fx 'Failed stage: CONTEXT' /tmp/legacy-direct-refusal-result >/dev/null
grep -Fx 'Error code: UPGRADE_CHECK_FAILED' /tmp/legacy-direct-refusal-result >/dev/null
[[ "$before" == "$(sha256sum /etc/pluton-agent.env /var/lib/pluton-agent/identity.json)" ]]
cp /tmp/pluton-install-private/provenance-original /opt/pluton-agent/.verified-install
for locale in C C.UTF-8 en_US.UTF-8; do
  LC_ALL="$locale" bash -Eeuo pipefail -c 'source installers/install-agent.sh; actual=$(verified_tree_digest /opt/pluton-agent); grep -Fx "tree=$actual" /opt/pluton-agent/.verified-install >/dev/null'
done
python3 - <<'PY'
import json
from pathlib import Path
p=json.loads(Path('/tmp/pluton-install-private/proof.json').read_text())
assert p == {'enrollments':1,'heartbeats':1,'polls':0}
print('PASS real fresh Ubuntu source build/install; private TLS enrollment and signed v0.7.0 heartbeat; no polling; original state preserved on reinstall refusal')
print('PASS standalone upgrader refuses legacy provenance before Node/activation; no automatic migration')
print('LIMITATION: disposable systemctl adapter; real systemd/cgroup startup and compatible production server were not tested')
PY
