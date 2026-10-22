# Disposable native Ubuntu acceptance

Status: **PENDING — no booted Ubuntu VM was available during local validation.**
Repeat on clean x86_64 Ubuntu Server 22.04 and the requested **24.04.5** image,
with native PID 1 systemd, unified cgroup v2 and AppArmor in its normal state.
Docker, WSL userlands and mocked systemctl are not substitutes. This procedure
authorizes no work on existing application servers. Use a new disposable VM with
no real identity, storage, infrastructure configuration or application data.

## Record and snapshot the clean VM

Record privately: reviewed Agent commit, VM provider, official ISO/cloud-image
SHA-256, `/etc/os-release`, `uname -r`, `uname -m`, `/proc/1/comm`,
`systemctl --version`, `findmnt /sys/fs/cgroup`, `cgroup.controllers`, locale and
package versions. Require x86_64, PID 1 `systemd`, `cgroup2`, and cpu/memory/pids
controllers. Record `systemctl is-system-running` and explain any unrelated
degraded units rather than silently accepting them. Take a clean snapshot.

Provision the utility packages in [operations](OPERATIONS.md). Add Python3,
OpenSSL and ACL tools for these synthetic tests; they are not Agent runtime
dependencies. Clone only this repository to root-protected `/root/pluton-agent`,
checkout the exact reviewed commit and confirm the worktree is clean. No global
Node/pnpm, other Pluton repository or production certificate/token is needed.

## Persistent synthetic loopback server

On this VM only, explicitly mark it disposable. Create protected fixture state
and a one-day synthetic certificate with a localhost SAN:

```sh
sudo touch /opt/pluton-disposable-native-vm
sudo chmod 0600 /opt/pluton-disposable-native-vm
sudo install -d -m 0700 /var/lib/pluton-synthetic-control-plane
sudo install -d -m 0755 /opt/pluton-synthetic-trust /srv/example-app
sudo bash -eu <<'SH'
umask 077
cd /var/lib/pluton-synthetic-control-plane
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost -keyout key.pem -out cert.pem
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > token
install -m 0644 cert.pem /opt/pluton-synthetic-trust/ca.pem
SH
```

Create `/etc/systemd/system/pluton-synthetic-control-plane.service` containing:

```ini
[Unit]
Description=Disposable synthetic Agent contract fixture
Before=pluton-agent.service
[Service]
ExecStart=/usr/bin/python3 /root/pluton-agent/tests/ubuntu/mock-control-plane.py --native-vm
Restart=on-failure
UMask=0077
[Install]
WantedBy=multi-user.target
```

Run `sudo systemctl daemon-reload`, enable/start that fixture, and require
`is-active` plus its private `ready` file. Native fixture mode requires the marker
and systemd PID 1, persists only synthetic HMAC identity/proof across reboot and
returns signed-request-validated **empty** polls. It never dispatches commands.
Do not copy its state or generated keys out of the disposable VM or into Git.

## Clean installation and real service activation

Run unprivileged `bash install-agent.sh --check --server https://localhost:18443
--allowed-root /srv/example-app --ca-file /opt/pluton-synthetic-trust/ca.pem`.
Record PASS and confirm no app/config/Agent state/unit was created. Then install:

```sh
sudo bash -c 'exec bash /root/pluton-agent/install-agent.sh \
  --server https://localhost:18443 --allowed-root /srv/example-app \
  --ca-file /opt/pluton-synthetic-trust/ca.pem --token-stdin \
  < /var/lib/pluton-synthetic-control-plane/token'
sudo systemd-analyze verify /etc/systemd/system/pluton-agent.service
systemctl is-enabled pluton-agent.service
systemctl is-active pluton-agent.service
```

Require real daemon-reload/enable/restart success, stable MainPID, no namespace,
permission or AppArmor errors, increasing authenticated heartbeat/poll counters,
version 0.7.0 and exclusions capability 1. Save only safe PASS/FAIL summaries.
Run a service-user `check` with the same explicit server/data/bin/roots/CA options;
require heartbeat increase without a poll increase from that probe (allow for the
independently running service's idle polls). Wrong CA/hostname must fail.

Check `stat`/`namei`: root-owned app/runtime/bin and unit, config `root:root 0600`,
state owned by pluton-agent `0700`, identity `0600`. Confirm nologin/nonroot account,
no docker/root/sudo/wheel membership, config unreadable and app unwriteable as the
service account. Use only a narrow synthetic ACL read/traverse fixture; do not
change application permissions to make this test pass. Test Source Access
canonical alias/protected-path rejection through the unprivileged unit suite.

## Native namespaces and cgroup enforcement

Inspect `systemctl show` and `/proc/<MainPID>/status`: correct User/Group,
NoNewPrivileges, empty effective capabilities, UMask and filesystem hardening.
Inspect `/proc/<MainPID>/mountinfo` for read-only `/usr` and `/etc`, and a separate
private `/tmp`. Use `sudo nsenter --target <MainPID> --mount --` with a harmless
write attempt under `/etc` to require EROFS; never change the unit or relax
AppArmor. Confirm the approved synthetic source can be read while protected and
undelegated paths remain denied by Agent policy. `ProtectSystem=full` is not a
global writable-path allowlist; report the actual boundary.

Require `ControlGroup=/system.slice/pluton-agent.service`, MainPID in its
`cgroup.procs`, and no unexpected child processes. Inspect `cpu.max`, `memory.max`
and `pids.max`. The shipped unit has no explicit CPU/memory/task ceilings; record
that fact rather than claiming bounded resources by default.

Take an installed-VM snapshot before this separate limit experiment:

```sh
sudo systemctl set-property --runtime pluton-agent.service \
  CPUQuota=50% MemoryMax=512M TasksMax=64
systemctl show pluton-agent.service -p CPUQuotaPerSecUSec -p MemoryMax -p TasksMax
sudo cat /sys/fs/cgroup/system.slice/pluton-agent.service/cpu.max
sudo cat /sys/fs/cgroup/system.slice/pluton-agent.service/memory.max
sudo cat /sys/fs/cgroup/system.slice/pluton-agent.service/pids.max
```

Require the actual kernel files to match (CPU quota/period ratio 0.5,
536870912 bytes, 64 tasks), continued healthy idle heartbeats and no controller
admission failure. Use a separate transient synthetic workload unit for bounded
CPU/task pressure; do not allocate uncontrolled memory or trigger OOM in Agent
state writes. Restore the installed snapshot before upgrade tests: runtime
resource drop-ins are deliberately outside the upgrader's standard-unit contract.
Do not weaken drop-in admission to permit this experiment.

## Restart, reboot and graceful shutdown

Hash private identity/config/provenance locally before a controlled restart.
Require stop to leave no MainPID/children, no SIGKILL/timeout, private state intact,
then restart to restore authenticated health without reenrollment. Reboot the
disposable VM; require both fixture and Agent enabled/active, stable service and
increasing proof counters with the same identity. Keep the VM test within the
synthetic certificate validity period. Certificate expiry is not bypassed.

## Upgrade, rollback and uninstall guards

Use clean root-protected Git checkouts of baseline and candidate commits and no
queued work. Run `sudo bash upgrade-agent.sh --check`; require read-only admission
and no changed private files. A same-commit transaction can test orchestration,
but record it explicitly; also test baseline-to-candidate app replacement.
Run the normal updater and confirm app/source provenance changed as expected,
identity/config/CA/receipts/policy remained unchanged, health succeeded and no
second enrollment occurred. Native tests supplement the crash/durability models.

With a VM snapshot, stop only the synthetic server to induce health failure,
run an upgrade and require nonzero status plus honest rollback outcome. Restore
the server and require the recorded prior app/provenance and original identity
to recover. Separately exercise `--rollback <exact-recorded-id>` after drain.
Never alter accepted hashes, delete holds/receipts or reset identity to force PASS.

Attempt fresh reinstall and require refusal with unchanged private files. Using
only synthetic snapshots, test missing standalone provenance refusal by upgrade
and uninstall. Restore exact fixture provenance, then normal uninstall must
preserve config/identity and a subsequent fresh install must still refuse.
An explicit disposable-only `uninstall --purge --force` may remove this synthetic
installation; recreate from the clean snapshot for an independent new install.
No real server device is revoked by local uninstall.

## Acceptance record

Record PASS/FAIL/PENDING for every section, exact image/commit, kernel/systemd
versions, controller files, reboot and identity preservation, server fixture
boundary, signed heartbeat/probe results and any rejected upgrade/rollback stage.
Retain private logs outside Git; publish only sanitized summaries. A failed or
unexecuted check blocks full native support claims. Before production onboarding,
separately validate the current compatible Server, approved Source Access and a
synthetic representative DB/SFTP backup and restored data. No production action
is performed by this procedure or the CI workflow.
