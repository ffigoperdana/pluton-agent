#!/usr/bin/env bash
set -Eeuo pipefail
[[ -f /opt/pluton-disposable-ubuntu-test && ${PLUTON_DISPOSABLE_INSTALL_TEST:-} == 1 && $EUID == 0 ]] || exit 90
candidate="${1:?pass the standalone source directory}"
[[ -f "$candidate/contracts/extraction-source.json" && ! -e "$candidate/backend" && ! -e "$candidate/frontend" ]] || exit 91
private=$(mktemp -d /tmp/legacy-refusal.XXXXXX)
trap 'cp "$private/original" /opt/pluton-agent/.verified-install; rm -rf -- "$private"' EXIT
cp /opt/pluton-agent/.verified-install "$private/original"
before=$(sha256sum /etc/pluton-agent.env /etc/systemd/system/pluton-agent.service /var/lib/pluton-agent/identity.json)
sed -i '/^distribution=/d' /opt/pluton-agent/.verified-install
cp /opt/pluton-agent/.verified-install "$private/legacy"
if bash "$candidate/install-agent.sh" uninstall --purge --force > "$private/uninstall-error" 2>&1; then exit 92; fi
grep -F 'Refusing to remove an unverified or non-standalone Agent' "$private/uninstall-error" >/dev/null
if bash "$candidate/upgrade-agent.sh" --check > "$private/upgrade-error" 2>&1; then exit 93; fi
grep -F 'monorepo installations require separate state-preserving migration approval' "$private/upgrade-error" >/dev/null
cmp /opt/pluton-agent/.verified-install "$private/legacy"
[[ "$before" == "$(sha256sum /etc/pluton-agent.env /etc/systemd/system/pluton-agent.service /var/lib/pluton-agent/identity.json)" ]]
printf 'PASS candidate refuses legacy upgrade and destructive uninstall; metadata, identity, config and unit unchanged\n'
