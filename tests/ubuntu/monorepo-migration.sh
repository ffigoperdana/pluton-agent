#!/usr/bin/env bash
# A real Server-monorepo Agent installation migrated by the reviewed standalone
# upgrader (--migrate-monorepo): refusal, preflight, failed-start rollback, success,
# explicit rollback to the exact monorepo installation and a second migration.
# Synthetic control plane/identity/data; only systemd is adapted.
set -Eeuo pipefail
[[ -f /opt/pluton-disposable-ubuntu-test && ${PLUTON_DISPOSABLE_INSTALL_TEST:-} == 1 && $EUID == 0 ]] || exit 90
monorepo="${1:?pass the read-only Server-monorepo source snapshot}"
[[ -f "$monorepo/installers/install-agent.sh" && -f "$monorepo/agent/package.json" && -f "$monorepo/pnpm-lock.yaml" ]] || exit 91
[[ ! -e "$monorepo/contracts/extraction-source.json" && ! -e /opt/pluton-agent && ! -e /workspace/.git ]] || exit 92
private=$(mktemp -d /tmp/pluton-monorepo-migration.XXXXXXXX)
chmod 0700 "$private"
cp -p /usr/bin/systemctl "$private/systemctl.native"
server_pid=''
stop_server() { [[ -z "$server_pid" ]] || { kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; server_pid=''; }; }
trap 'stop_server; cp -p "$private/systemctl.native" /usr/bin/systemctl' EXIT
closed_fields() {
	grep -E '^(Failed stage:|Error code:|Rollback:|Previous Agent preserved:)' "$1" || true
	# Disposable synthetic fixture only: the guard text, checkout state and layout
	# contain no production data and explain a refusal the closed fields hide.
	/opt/pluton-agent/runtime/bin/node -e '
const u = require("/workspace/installers/lib/upgrade-agent.cjs");
try { const c = u.productionContext("/workspace", process.argv[1]); c.preflight(); u.assertLocallyDrained(c); console.log("fixture preflight now passes"); }
catch (e) { console.log("fixture detail:", e.message); }' "${2:-migrate}" || true
	git status --porcelain --untracked-files=normal | head -n 10 || true
	ls -la /opt/pluton-agent /var/lib/pluton-agent | head -n 40 || true
}

# 1. Install exactly as the Server monorepo installer did, from its own snapshot.
mkdir -p /tmp/pluton-install-private /opt/test-trust /srv/example-app /run/systemd/system
chmod 0700 /tmp/pluton-install-private
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost' -keyout /tmp/pluton-install-private/key.pem \
  -out /tmp/pluton-install-private/cert.pem >/dev/null 2>&1
cp /tmp/pluton-install-private/cert.pem /opt/test-trust/ca.pem
chmod 0644 /opt/test-trust/ca.pem
python3 -c 'import secrets;print(secrets.token_urlsafe(32))' > /tmp/pluton-install-private/token
python3 tests/ubuntu/mock-control-plane.py --expect-agent-version 0.7.0 &
server_pid=$!
for attempt in {1..50}; do [[ ! -f /tmp/pluton-install-private/ready ]] || break; sleep 0.1; done
[[ -f /tmp/pluton-install-private/ready ]]
# The monorepo installer's fresh build resolves `node` from PATH (the "isolated
# fresh-build PATH defect" in docs/EXTRACTION_AUDIT.md), so its hosts had one.
# Provide the same official, checksum-pinned v22.18.0 for this one command only.
build_node=/opt/pluton-monorepo-build-node
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --retry 3 \
  --output "$private/node.tar.xz" https://nodejs.org/dist/v22.18.0/node-v22.18.0-linux-x64.tar.xz
printf '%s  %s\n' c1bfeecf1d7404fa74728f9db72e697decbd8119ccc6f5a294d795756dfcfca7 "$private/node.tar.xz" | sha256sum --check --status -
mkdir -p "$build_node"
tar -xJf "$private/node.tar.xz" -C "$build_node" --strip-components=1
PATH="$build_node/bin:$PATH" bash "$monorepo/installers/install-agent.sh" --server https://localhost:18443 \
  --allowed-root /srv/example-app --ca-file /opt/test-trust/ca.pem --token-stdin < /tmp/pluton-install-private/token
rm -rf -- "$build_node" "$private/node.tar.xz"
if command -v node >/dev/null 2>&1; then printf 'Build Node leaked onto PATH\n' >&2; exit 103; fi
stop_server
rm -f /tmp/pluton-install-private/ready
# `! cmd` would not trip errexit; make the refusal explicit.
if grep -q '^distribution=' /opt/pluton-agent/.verified-install; then exit 102; fi
[[ $(/opt/pluton-agent/runtime/bin/node -v) == v22.18.0 ]]
grep -F 'AGENT_VERSION = "0.7.0"' /opt/pluton-agent/app/dist/inventory.js >/dev/null
cp -p /opt/pluton-agent/.verified-install "$private/monorepo-provenance"
printf 'PASS real Server-monorepo installation: no standalone marker, private Node v22.18.0, Agent 0.7.0\n'

# 2. Candidate checkout and adapters, as for every standalone upgrade fixture.
git init -q
git config user.name 'Synthetic Monorepo Migration'
git config user.email 'test@example.invalid'
git add -- .
git commit -qm 'Synthetic reviewed standalone source'
touch /tmp/pluton-runtime-fixture-enabled
install -m 0755 tests/ubuntu/systemctl-upgrade-fixture.sh /usr/bin/systemctl
mkdir -p /etc/pluton-agent
printf 'synthetic policy bytes\n' > /etc/pluton-agent/preservation-policy.txt
chmod 0644 /etc/pluton-agent/preservation-policy.txt
printf '{"fixture":"preserve-receipt"}\n' > /var/lib/pluton-agent/source-access-fixture.json
chown pluton-agent:pluton-agent /var/lib/pluton-agent/source-access-fixture.json
chmod 0600 /var/lib/pluton-agent/source-access-fixture.json
protected='/etc/pluton-agent.env /etc/systemd/system/pluton-agent.service /var/lib/pluton-agent/identity.json /var/lib/pluton-agent/source-access-fixture.json /etc/pluton-agent/preservation-policy.txt'
# shellcheck disable=SC2086
before=$(sha256sum $protected)
# shellcheck disable=SC2086
assert_preserved() { [[ "$before" == "$(sha256sum $protected)" ]]; }
assert_monorepo() {
	cmp /opt/pluton-agent/.verified-install "$private/monorepo-provenance"
	[[ $(/opt/pluton-agent/runtime/bin/node -v) == v22.18.0 && ! -e /opt/pluton-agent/.upgrade-lock ]]
	grep -F 'AGENT_VERSION = "0.7.0"' /opt/pluton-agent/app/dist/inventory.js >/dev/null
	assert_preserved
}
python3 tests/ubuntu/mock-control-plane.py --existing-identity &
server_pid=$!
sleep 1

# 3. The ordinary path still refuses; the explicit preflight passes read-only.
if bash upgrade-agent.sh --check > "$private/plain-check.log" 2>&1; then exit 93; fi
grep -F 'monorepo installations require separate state-preserving migration approval' "$private/plain-check.log" >/dev/null
if bash upgrade-agent.sh > "$private/plain-upgrade.log" 2>&1; then exit 94; fi
assert_monorepo
bash upgrade-agent.sh --migrate-monorepo --check | grep -F 'Read-only local monorepo migration preflight PASS' >/dev/null
assert_monorepo
printf 'PASS ordinary upgrade refused; explicit migration preflight passed without changes\n'

# 4. A start failure restores the exact monorepo app, runtime and provenance.
touch /tmp/pluton-runtime-fixture-fail-start
if bash upgrade-agent.sh --migrate-monorepo > "$private/failed-start.log" 2>&1; then exit 95; fi
if ! grep -Fx 'Failed stage: SERVICE_START' "$private/failed-start.log" >/dev/null ||
   ! grep -Fx 'Rollback: SUCCESS' "$private/failed-start.log" >/dev/null; then
	closed_fields "$private/failed-start.log"
	exit 96
fi
assert_monorepo
printf 'PASS failed-start migration restored the exact monorepo installation\n'

# 5. Successful migration: same identity/config/unit/policy, standalone provenance.
bash upgrade-agent.sh --migrate-monorepo > "$private/migrate.log" 2>&1 || { closed_fields "$private/migrate.log"; exit 97; }
grep -F 'Monorepo installation migrated to the standalone distribution.' "$private/migrate.log" >/dev/null
# The adapter reports a started service with a fictitious MainPID and no cgroup,
# which no later preflight can verify against /proc. Stop it before the next
# transaction, as an operator would after the drained pilot.
/usr/bin/systemctl stop
id=$(sed -n 's/.*Upgrade ID: \([0-9a-f-]*\)\..*/\1/p' "$private/migrate.log")
[[ "$id" =~ ^[0-9]{14}-[a-f0-9]{12}-[a-f0-9]{12}$ ]]
grep -F '"migration": "monorepo"' "/var/lib/pluton-agent-upgrades/$id/receipt.json" >/dev/null
cmp "/var/lib/pluton-agent-upgrades/$id/verified-install" "$private/monorepo-provenance"
grep -Fx 'distribution=pluton-agent-standalone-v1' /opt/pluton-agent/.verified-install >/dev/null
[[ $(/opt/pluton-agent/runtime/bin/node -v) == v22.23.4 && ! -e /opt/pluton-agent/.upgrade-lock ]]
grep -F "AGENT_VERSION = \"$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' agent/package.json)\"" /opt/pluton-agent/app/dist/inventory.js >/dev/null
assert_preserved
(
	source installers/install-agent.sh
	grep -Fx "tree=$(verified_tree_digest /opt/pluton-agent)" /opt/pluton-agent/.verified-install >/dev/null
)
if bash upgrade-agent.sh --migrate-monorepo --check > "$private/again.log" 2>&1; then exit 98; fi
grep -F 'Already a standalone installation' "$private/again.log" >/dev/null
bash upgrade-agent.sh --check > "$private/standalone-check.log" 2>&1 || { closed_fields "$private/standalone-check.log" check; exit 104; }
grep -F 'Read-only local preflight PASS' "$private/standalone-check.log" >/dev/null
printf 'PASS migration kept identity/config/unit/policy/receipts, added only the standalone marker and now uses the normal upgrade path\n'

# 6. Explicit rollback returns the exact monorepo installation; migrating again works.
bash upgrade-agent.sh --rollback "$id" > "$private/rollback.log" 2>&1 || { closed_fields "$private/rollback.log" rollback; exit 99; }
assert_monorepo
(
	source installers/install-agent.sh
	grep -Fx "tree=$(verified_tree_digest /opt/pluton-agent)" /opt/pluton-agent/.verified-install >/dev/null
)
if bash upgrade-agent.sh --check > "$private/after-rollback.log" 2>&1; then exit 100; fi
grep -F 'monorepo installations require separate state-preserving migration approval' "$private/after-rollback.log" >/dev/null
bash upgrade-agent.sh --migrate-monorepo > "$private/migrate-again.log" 2>&1 || { closed_fields "$private/migrate-again.log"; exit 101; }
grep -Fx 'distribution=pluton-agent-standalone-v1' /opt/pluton-agent/.verified-install >/dev/null
assert_preserved
stop_server
python3 - <<'PY'
import json
from pathlib import Path
proof = json.loads(Path('/tmp/pluton-install-private/proof.json').read_text())
assert proof['enrollments'] == 1 and proof['polls'] == 0 and proof['heartbeats'] >= 3, proof
PY
[[ ! -e /tmp/pluton-install-private/unexpected-reenrollment ]]
printf 'PASS real monorepo -> standalone migration, failed-start and explicit rollback to the exact monorepo installation, repeat migration, one enrollment and signed heartbeats; systemd adapter only\n'
