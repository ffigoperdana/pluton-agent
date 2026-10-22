#!/usr/bin/env bash
# Mutates only this disposable fixture's synthetic install; no native systemd.
set -Eeuo pipefail
[[ -f /opt/pluton-disposable-ubuntu-test && ${PLUTON_DISPOSABLE_INSTALL_TEST:-} == 1 && $EUID == 0 ]] || exit 90
before=$(sha256sum /etc/pluton-agent.env /var/lib/pluton-agent/identity.json /etc/systemd/system/pluton-agent.service /opt/pluton-agent/.verified-install)
if bash recover-agent-install.sh --check >/tmp/recovery-refusal.log 2>&1; then exit 91; fi
[[ "$before" == "$(sha256sum /etc/pluton-agent.env /var/lib/pluton-agent/identity.json /etc/systemd/system/pluton-agent.service /opt/pluton-agent/.verified-install)" ]]
private=$(mktemp -d /tmp/pluton-synthetic-recovery.XXXXXXXX)
chmod 0700 "$private"
# Recovery deliberately uses a protected PATH. Adapt the manager at that exact
# path ONLY inside this disposable image, restoring the real binary on exit.
cp -p /usr/bin/systemctl "$private/systemctl.native"
trap 'cp -p "$private/systemctl.native" /usr/bin/systemctl' EXIT
install -m 0755 tests/ubuntu/systemctl-fixture.sh /usr/bin/systemctl
cp -p /etc/systemd/system/pluton-agent.service "$private/unit"
# Manufacture an identity-less failed-first-install shape in this fixture only.
systemctl stop pluton-agent.service
mv /var/lib/pluton-agent "$private/original-state"
install -d -o pluton-agent -g pluton-agent -m 0700 /var/lib/pluton-agent
rm /etc/systemd/system/pluton-agent.service
bash recover-agent-install.sh --check
if bash recover-agent-install.sh --quarantine >/tmp/recovery-confirmation.log 2>&1; then exit 92; fi
bash recover-agent-install.sh --quarantine --confirm-unenrolled
[[ ! -e /opt/pluton-agent && ! -e /etc/pluton-agent.env && ! -e /var/lib/pluton-agent ]]
quarantine=$(find /var/lib -maxdepth 1 -type d -name 'pluton-agent-partial.*')
[[ -n "$quarantine" && "$(stat -c '%u:%a' "$quarantine")" == 0:700 ]]
# Restore exact synthetic files so the original legacy refusal checks still run.
mv "$quarantine/install" /opt/pluton-agent
mv "$quarantine/config.env" /etc/pluton-agent.env
mv "$quarantine/state" /var/lib/pluton-agent
rmdir /var/lib/pluton-agent
mv "$private/original-state" /var/lib/pluton-agent
cp -p "$private/unit" /etc/systemd/system/pluton-agent.service
systemctl start pluton-agent.service
[[ "$before" == "$(sha256sum /etc/pluton-agent.env /var/lib/pluton-agent/identity.json /etc/systemd/system/pluton-agent.service /opt/pluton-agent/.verified-install)" ]]
rmdir "$quarantine"
printf 'PASS real root ownership/integrity/empty-state recovery guards, private same-filesystem quarantine and exact synthetic restoration; systemd adapter only\n'
