# Node 22.23.4 private runtime security patch

## Scope and trust

The [official Node 22.23.4 release](https://nodejs.org/en/blog/release/v22.23.4/)
is the October 21, 2026 security release. See the upstream
[security advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases).
The installer downloads only `node-v22.23.4-linux-x64.tar.xz` over verified HTTPS,
checks its version-specific official SHASUMS256 index **and** this reviewed pin
before extraction, then checks the actual executable version:

```text
1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce
```

This is not a detached-signature verification claim. Linux x86_64 remains the
only supported installer architecture. No system Node/global tools are changed.
Agent capability/protocol **0.7.0**, pnpm **10.20.0**, Restic **0.19.1**, rclone
**1.75.1**, the dependency lockfile and golden HMAC/API fixtures remain unchanged.
Only transport tests change under `agent/src`; the source-delta manifest records
their new hash. Runtime implementation and Source Access authority are unchanged.

Pin inventory: installer and partial recovery; standalone upgrade bootstrap and
runtime transaction; release manifest; CI; Ubuntu fresh/runtime/network fixtures;
downloader fixtures and pin-contract tests; current operator/developer docs.
Retained 22.18.0 references mean an explicitly admitted prior standalone runtime,
a synthetic old-runtime fixture or historical audit evidence. They are not a
current installation pin. The old fixture archive uses its separate official
SHA-256; production download pins cannot be overridden through the environment.
The existing `@types/node` 22.18.13 remains a frozen build dependency, not a runtime pin.

## Fresh installation on a new host

Use the [prerequisites and trust procedure](OPERATIONS.md) and a reviewed immutable
commit containing this patch. Example values below are placeholders for local
operator input, never production defaults:

```bash
cd /srv/pluton-agent
git checkout --detach <approved-full-commit>
bash install-agent.sh --check --server https://<approved-server> --allowed-root /<approved-source>
sudo bash install-agent.sh --server https://<approved-server> --allowed-root /<approved-source>
```

Enter a newly issued one-time token only at the private prompt. For a private CA,
add the same approved `--ca-file /<protected-ca.pem>` to both invocations. Do not
put tokens in command arguments, logs or tickets. The fresh-install guard still
refuses existing identity/config/state/app/unit. It is not an update procedure.

Node, Restic and rclone acquisition/build happen before final state creation.
The GET-only downloader retains four attempts, 2/4/8-second backoff, 30-second
connect, 120-second transfer and 300-second total artifact budgets. TLS/checksum
errors remain terminal. See [partial recovery](INSTALLER_DOWNLOADS.md) for the
explicit protected quarantine procedure after a later enrollment failure. Never
erase an identity or unknown partial state to retry installation.

## Existing enrolled standalone installation

The previous upgrader admitted only the currently pinned Node and replaced only
the application; changing the install pin alone would refuse existing enrolled
22.18.0 installations. The reviewed extension admits exactly protected standalone
22.18.0 and 22.23.4 provenance. It builds from a clean committed source archive,
downloads/verifies the new runtime in private staging when required, verifies
service-account execution, and adds runtime replacement to the existing drained
application transaction. It does not invoke installer `main`, enroll, write
configuration/unit, update Restic/rclone or copy back old identity/policy state.

The existing protected provenance, full-tree digest, root ownership, permissions,
source commit, service contract, cgroup drain, capability/receipt/policy fences,
disk admission, durability and authenticated heartbeat checks remain mandatory.
Reserve at least 2 GiB plus twice the installed app/runtime size on both `/opt`
and backup filesystems; accumulated builds/history can require substantially more.
Unknown/custom versions or installations fail closed.

After separate operational approval, pause plans and settle queued/running backup
and Source Access operations on the Server. Keep them paused through validation.
Use the [complete upgrade contract](AGENT_UPGRADE.md), including the safely drained
first-upgrade requirement for a running Agent without upgrade protocol v1:

```bash
cd /srv/pluton-agent
git checkout --detach <approved-full-commit>
sudo bash upgrade-agent.sh --check
sudo bash upgrade-agent.sh
```

`--check` is read-only and sends no heartbeat or download. The actual upgrade may
stop/start only its eligible service as part of the separately approved operator
procedure. No such action is performed on a real Agent by this repository task.
No enrollment token is needed. Do not run the fresh installer as a workaround.

## Verification and rollback

Before upgrading, privately record identity/config/unit/policy/receipt digests in
a root-only local evidence directory. Do not display their contents or publish
digests/paths revealing infrastructure. Compare unchanged files afterwards;
Agent IDs, selected roots, host delegation receipts and approvals must remain
the same. Normal logs can grow; do not require identical log bytes. The upgrader's
protected-state digest already enforces identity and authority preservation.

After a successful upgrade, an operator verifies locally:

```bash
/opt/pluton-agent/runtime/bin/node -v
/opt/pluton-agent/runtime/bin/node -p 'require("/opt/pluton-agent/app/package.json").version'
systemctl is-active pluton-agent.service
systemctl is-enabled pluton-agent.service
```

Expected: `v22.23.4`, `0.7.0`, `active`, `enabled`. Confirm a successful
authenticated heartbeat, the same Agent/device Online in Pluton Server, and
unchanged Source Access mode/allowed roots/approvals/receipts before resuming
plans. Do not reenroll to obtain an Online status. The upgrade never enables or
rewrites a previously disabled/custom service; investigate unexpected status.

Runtime transactions have receipt version **2**, distinct from application-only
version **1**. The previous app/runtime/provenance and verified failed/candidate
trees are retained privately. Each app/runtime rename is atomic individually;
the combined exchange is journaled, not one atomic operation. A root-owned 0500,
single-link copy of the verified previous Node executable in `.upgrade-lock`,
bound to its protected SHA-256 receipt, bootstraps rollback even during a gap
where the installed runtime path is absent. Recovery uses the patched checkout.

Ordinary failed activation/start/health checks attempt exact old app/runtime and
provenance restoration while the hold remains closed. Interrupted transactions
require confirming the owner is gone, keeping plans paused and reviewing the
exact root-private receipt before invoking:

```bash
sudo bash upgrade-agent.sh --rollback <exact-upgrade-id>
```

Rollback verifies recorded backup hashes, current/previous runtime trees and
protected state. It never restores historical identity/config/policy/receipts.
Changed authority, unknown/corrupt artifacts, live owners, missing/corrupt anchors,
uncertain hold release or durability failure are stop conditions: retain evidence
and obtain a separate recovery review. Do not delete holds, edit provenance,
overwrite the runtime binary in place or force a fresh install. Rolling back
to 22.18.0 restores a vulnerable runtime and requires prompt reviewed remediation.
Monorepo provenance remains excluded; do not add a standalone marker manually.
The older Ubuntu production Agent must remain on its separately reviewed path.

## Server installation commit pin

New fresh-install commands must resolve to a reviewed commit containing this
patch. If the Server's `AGENT_INSTALL_COMMIT` still pins an earlier commit, its
deployment owner must update that pin after separate review/publication approval
and regenerate wizard commands. Existing copied commands retain their old pin.
An enrolled Agent uses the reviewed local upgrade checkout; changing the Server
pin or regenerating a wizard command does not upgrade it or require reenrollment.
This local-only task changes no Server configuration and publishes no commit.

## Validation record and boundaries

The matrix uses disposable Ubuntu 22.04/24.04 x86_64 containers, real official
Node binaries, pinned private tools and a synthetic TLS/HMAC control plane.
Systemd activation/cgroup responses use explicitly guarded adapters; no booted
systemd VM or Ubuntu 24.04.5 Server ISO acceptance is claimed. Hosted CI is
configured, not dispatched by this local task. See the
[native acceptance gate](NATIVE_SYSTEMD_ACCEPTANCE.md).

Local validation on 2026-10-23 starts from standalone main
`8bc74a7a6f1f436bf7920a3712b0e939665878b8` on branch
`codex/node-22-23-4-security`. Container fixtures make their own clean synthetic
Git commits of public source for provenance/build/package checks; these are not
published release commits. Results for both releases:

| Check | Ubuntu 22.04 | Ubuntu 24.04 |
| --- | --- | --- |
| Actual private Node 22.23.4, checksum/version assertions, source build and typecheck | PASS | PASS |
| Agent suite: signing/poll/receipts, exclusions, filesystem Restic, rclone/tool adapters, DB/hooks and Source Access authorization/cancellation | 178 pass, 0 skip | 178 pass, 0 skip |
| Source, golden protocol, release and runtime-pin contracts | 9 pass, 0 skip | 9 pass, 0 skip |
| Upgrade fault-injection, provenance deadline, permissions and three locales | 70 pass, 0 skip | 70 pass, 0 skip |
| Installer/downloader shell and real local HTTPS regressions, DNS recovery, interruption, bad checksum, TLS and existing-state refusal | PASS | PASS |
| Fresh TLS enrollment and signed heartbeat; partial recovery, quarantine and monorepo refusal | PASS (manager adapter) | PASS (manager adapter) |
| Real 22.18.0 to 22.23.4 upgrade: failed-start rollback, recovery through absent runtime, final version/provenance and exact identity/config/unit/policy/receipt hashes, signed heartbeat with no reenrollment | PASS (manager adapter) | PASS (manager adapter) |
| Final standalone admission guard: accepted patched provenance, rejected monorepo through the context factory and direct CLI before build/service access | PASS | PASS |
| Two package builds: identical release manifests and verified source/app artifact hashes | PASS | PASS |
| Delayed IPv4/IPv6 SYN fallback, exactly one POST per verified selected connection, private network namespace | PASS | PASS |

The Agent suite includes 17 transport scenarios: IPv4/IPv6/dual stack, slow DNS,
15/30-second shared deadlines, delayed TCP/TLS, expired/untrusted/hostname-invalid
certificates, reverse-proxy HTML/status/redirect rejection, redacted diagnostics,
read-only network-check and no credential-bearing replay. The routing acceptance
adds controlled kernel SYN timing with `--network none --cap-add NET_ADMIN` on
the validated images, without host networking or mounts.

The final admission guard was checked separately on both validated images,
including a repeat of all 70 upgrade/provenance/locale tests (zero skips).
To repeat the CI targets from a clean public source checkout:

```bash
for ubuntu in 22.04 24.04; do
  docker build --platform linux/amd64 --target validation --build-arg UBUNTU_VERSION="$ubuntu" -f tests/ubuntu/Dockerfile -t "pluton-agent-validation:local-$ubuntu" .
  docker build --platform linux/amd64 --target runtime-upgrade --build-arg UBUNTU_VERSION="$ubuntu" -f tests/ubuntu/Dockerfile -t "pluton-agent-runtime:local-$ubuntu" .
  docker build --platform linux/amd64 --target network-routing --build-arg UBUNTU_VERSION="$ubuntu" -f tests/ubuntu/Dockerfile -t "pluton-agent-routing:local-$ubuntu" .
  docker run --rm --network none --cap-add NET_ADMIN "pluton-agent-routing:local-$ubuntu"
done
```

External production
Cloudflare/BunkerWeb, real database servers, SFTP/S3 endpoints, Server UI Online
status and real Agent upgrades require a separately approved pilot. Local tests
cover proxy-style HTTPS responses, protocol signatures, backup/tool integrations,
Source Access and negative authorization cases within their synthetic boundaries.

## Changed files

Runtime and upgrade:

```text
installers/install-agent.sh
installers/upgrade-agent.sh
installers/lib/upgrade-agent.cjs
installers/lib/upgrade-runtime.cjs
installers/lib/recover-partial.sh
```

Verification, packaging and CI:

```text
agent/src/transport.test.ts
contracts/standalone-source-v1.json
installers/tests/dependency-https.py
installers/tests/install-agent.test.sh
installers/tests/upgrade-agent.test.cjs
scripts/package-release.mjs
scripts/tests/runtime-pins.test.mjs
.github/workflows/ci.yml
tests/ubuntu/Dockerfile
tests/ubuntu/fresh-install.sh
tests/ubuntu/mock-control-plane.py
tests/ubuntu/network-routing.mjs
tests/ubuntu/runtime-upgrade.sh
tests/ubuntu/systemctl-upgrade-fixture.sh
```

Instructions and documentation:

```text
AGENTS.md
README.md
docs/AGENT_UPGRADE.md
docs/EXTRACTION_AUDIT.md
docs/INSTALLER_DOWNLOADS.md
docs/NETWORK_ENROLLMENT.md
docs/NODE_RUNTIME_SECURITY.md
docs/OPERATIONS.md
docs/RELEASES.md
docs/UBUNTU_VALIDATION.md
```
