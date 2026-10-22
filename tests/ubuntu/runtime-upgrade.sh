#!/usr/bin/env bash
# Real old/new private runtimes and transaction filesystem, adapted systemd only.
set -Eeuo pipefail
[[ -f /opt/pluton-disposable-ubuntu-test && ${PLUTON_DISPOSABLE_INSTALL_TEST:-} == 1 && $EUID == 0 ]] || exit 90
[[ ! -e /opt/pluton-agent && ! -e /workspace/.git ]] || exit 91
private=$(mktemp -d /tmp/pluton-runtime-upgrade.XXXXXXXX)
chmod 0700 "$private"
cp -p /usr/bin/systemctl "$private/systemctl.native"
server_pid=''
trap '[[ -z "$server_pid" ]] || kill "$server_pid" 2>/dev/null || true; cp -p "$private/systemctl.native" /usr/bin/systemctl' EXIT
# Manufacture a prior standalone release ONLY in the disposable source copy.
# Both archive pins are official Linux x64 hashes, never environment overrides.
previous_source=$(mktemp -d /opt/pluton-synthetic-previous-source.XXXXXXXX)
chmod 0755 "$previous_source" # Public source must be readable by preflight's nobody account.
cp -a /workspace/. "$previous_source/"
sed -i "s/readonly NODE_VERSION='v22.23.4'/readonly NODE_VERSION='v22.18.0'/; s/1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce/c1bfeecf1d7404fa74728f9db72e697decbd8119ccc6f5a294d795756dfcfca7/" "$previous_source/installers/install-agent.sh"
( cd "$previous_source"; PLUTON_EXPECT_NODE_VERSION=v22.18.0 bash tests/ubuntu/fresh-install.sh )
[[ $(/opt/pluton-agent/runtime/bin/node -v) == v22.18.0 ]]
git init
git config user.name 'Synthetic Runtime Upgrade'
git config user.email 'test@example.invalid'
git add -- .
git commit -m 'Synthetic reviewed runtime security source'
touch /tmp/pluton-runtime-fixture-enabled
install -m 0755 tests/ubuntu/systemctl-upgrade-fixture.sh /usr/bin/systemctl
mkdir -p /etc/pluton-agent
printf 'synthetic policy bytes\n' > /etc/pluton-agent/preservation-policy.txt
chmod 0644 /etc/pluton-agent/preservation-policy.txt
printf '{"fixture":"preserve-receipt"}\n' > /var/lib/pluton-agent/source-access-fixture.json
chown pluton-agent:pluton-agent /var/lib/pluton-agent/source-access-fixture.json
chmod 0600 /var/lib/pluton-agent/source-access-fixture.json
before=$(sha256sum /etc/pluton-agent.env /etc/systemd/system/pluton-agent.service /var/lib/pluton-agent/identity.json /var/lib/pluton-agent/source-access-fixture.json /etc/pluton-agent/preservation-policy.txt)
python3 tests/ubuntu/mock-control-plane.py --existing-identity &
server_pid=$!
sleep 1
bash upgrade-agent.sh --check
[[ "$before" == "$(sha256sum /etc/pluton-agent.env /etc/systemd/system/pluton-agent.service /var/lib/pluton-agent/identity.json /var/lib/pluton-agent/source-access-fixture.json /etc/pluton-agent/preservation-policy.txt)" ]]
# A start failure must restore old app/runtime/provenance, preserving enrollment.
touch /tmp/pluton-runtime-fixture-fail-start
if bash upgrade-agent.sh > "$private/failed-start.log" 2>&1; then exit 92; fi
if ! grep -Fx 'Failed stage: SERVICE_START' "$private/failed-start.log" >/dev/null ||
   ! grep -Fx 'Error code: AGENT_START_FAILED' "$private/failed-start.log" >/dev/null ||
   ! grep -Fx 'Rollback: SUCCESS' "$private/failed-start.log" >/dev/null; then
	# Only closed diagnostic fields may enter the public fixture log.
	grep -E '^(Failed stage:|Error code:|Rollback:|Previous Agent preserved:)' "$private/failed-start.log" || true
	exit 93
fi
[[ $(/opt/pluton-agent/runtime/bin/node -v) == v22.18.0 && ! -e /opt/pluton-agent/.upgrade-lock ]]
grep -Fx node=v22.18.0 /opt/pluton-agent/.verified-install >/dev/null
printf 'PASS failed-start restored old runtime and provenance\n'
# Kill-equivalent interruption at the runtime rename gap; bootstrap rollback
# must work while /opt/pluton-agent/runtime/bin/node is absent.
/opt/pluton-agent/runtime/bin/node - <<'NODE'
const { productionContext, upgrade } = require('./installers/lib/upgrade-agent.cjs');
const fs = require('node:fs');
const c = productionContext('/workspace');
c.checkpoint = (phase) => { if (phase === 'runtime-old-moved') throw Object.assign(new Error('synthetic interruption'), {interrupted:true}); };
try { upgrade(c); throw Error('interruption did not occur'); }
catch (error) { if (!error.interrupted) throw error; }
if (fs.existsSync('/opt/pluton-agent/runtime')) throw Error('runtime gap was not exercised');
NODE
interrupted_id=$( /opt/pluton-agent/.upgrade-lock/node -p "require('/opt/pluton-agent/.upgrade-lock/owner.json').id" )
bash upgrade-agent.sh --rollback "$interrupted_id"
[[ $(/opt/pluton-agent/runtime/bin/node -v) == v22.18.0 ]]
bash upgrade-agent.sh
[[ $(/opt/pluton-agent/runtime/bin/node -v) == v22.23.4 && ! -e /opt/pluton-agent/.upgrade-lock ]]
grep -Fx node=v22.23.4 /opt/pluton-agent/.verified-install >/dev/null
grep -Fx node_archive=1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce /opt/pluton-agent/.verified-install >/dev/null
[[ "$before" == "$(sha256sum /etc/pluton-agent.env /etc/systemd/system/pluton-agent.service /var/lib/pluton-agent/identity.json /var/lib/pluton-agent/source-access-fixture.json /etc/pluton-agent/preservation-policy.txt)" ]]
[[ ! -e /tmp/pluton-install-private/unexpected-reenrollment ]]
python3 - <<'PY'
import json
from pathlib import Path
p=json.loads(Path('/tmp/pluton-install-private/proof.json').read_text())
assert p['enrollments']==1 and p['polls']==0 and p['heartbeats']>=2
PY
source installers/install-agent.sh
actual=$(verified_tree_digest /opt/pluton-agent)
grep -Fx "tree=$actual" /opt/pluton-agent/.verified-install >/dev/null
printf 'PASS real 22.18.0 -> 22.23.4 runtime upgrade, failed-start rollback, anchored rename-gap recovery, exact identity/config/unit/policy/receipt preservation and signed heartbeat; systemd adapter only\n'
