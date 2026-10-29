# Post-dump backup reliability: standalone semantic port

Source: [Pluton PR #53](https://github.com/ffigoperdana/pluton/pull/53), merge
`edcfe5fba3a2eb47730307fa53c90730177b5430` (feature head `c4f25489afffb23d2091b3a5b9cced923ff5ec89`).
Target baseline: refreshed standalone main `32eb70ab3e30390234d2fd70c9db3b565ab85811`.
Branch: `codex/port-post-dump-backup-reliability`.

## Defect and incident evidence

A successful native MySQL dump can be followed by an exception from the required
authenticated cancellation/lease check before repository preparation. The old
stage still says `database-dump`, so the untyped fallback becomes
`database-dump/unexpected`. The original standalone Agent reproduced this using
Oracle MySQL 8.4.11, native mysqldump and real Restic/Rclone tools: an injected
post-dump 503 produced that exact stage/code and no repository preparation.

This confirms the code defect. It does not prove the exact historical production
trigger. Intermittent progress-event 429s and other status HTTP 200s do not identify
the exception at that boundary or prove every status response was valid/complete.
No production host, database, backup repository or original source was accessed.
Public fixtures use synthetic infrastructure only.

## Semantic port and preserved differences

The standalone `network.ts` connector remains unchanged: verified TLS connection
racing, origin restrictions, DNS deadlines, address-family behavior and private
single-use sockets precede sending signed HTTP bytes. No monorepo connection or
transport implementation replaced it. `AgentTransport.post` accepts an optional
shorter request deadline through the same DNS/connect/response abort signal.

Standalone `AgentNetworkError` categories are translated only by command status:
transient DNS/connect/interruption/timeout errors can retry; certificate and
authorization errors are terminal. Invalid/oversized bodies never retry. Other
client endpoints retain strict enrollment/result validation and the standalone
void ACK/events/completion contract. No enrollment, ACK, poll, event or completion
automatic retry was added.

Status checks share only in-flight requests for the exact command/token and never
cache a settled response. Lease deadlines are also keyed by exact command/token,
an additional binding over the source implementation's command-ID deadline map.
At most three attempts use 250/750 ms backoff, five seconds per request and a
15-second overall budget, capped by the known lease expiration. Each attempt
creates fresh timestamp/nonce/HMAC inputs. Optional returned deadlines are checked;
legacy cancellation-only responses use the existing authenticated 60-second
renewal policy, conservatively measured from request start at SQLite precision.

The post-dump stage is set before the required status check. Typed failures become
`post-dump-status-check` or `command-status-check`, with the source PR's closed
codes. Credential finalization failure is separate from dump execution. Terminal
status failure stops native work and cannot become a parent-lookup fallback.
Owned process-tree termination, SQL/credential cleanup and real cancellation are
preserved. Native work does not continue on an authorization failure.

Progress has one in-flight event, one coalesced pending event and one-second
pacing. Initial accepted progress is best-effort; mandatory ACK still happens
first. Final completion is persisted before sending, remains mandatory, and
restart replay sends the stored completion without repeating execution.

The source-diagnostics error mapping conflict was resolved by retaining all
standalone relative-path metadata and negotiated completion fields. Existing
Source Access roots, policy/receipts, capability advertisement (0.7.1), identity,
durable completions and request signatures are unchanged. The explicit independent
source-hash delta records changed/new Agent files; extraction hashes and original
HMAC/exclusion vectors are untouched. No runtime dependencies were added.

Not copied: backend code, server/frontend packages, monorepo HTTP error classes,
deployment scripts or installer implementations. No symlink/download/export,
schedule, database credential, source root or repository mutation feature was added.

## Differential validation

Validation uses pinned Node 22.23.4, pnpm 10.20.0 and the frozen standalone
lockfile in disposable Linux containers, without production data. Actual native
MySQL 8.4.11/mysqldump, Restic 0.19.1 and Rclone 1.75.1 exercise 24 cases. The
original standalone build separately reproduces the misleading classification.

| Requirement | Monorepo PR #53 | Standalone port | Verification |
| --- | --- | --- | --- |
| Post-dump status retries | Three bounded attempts | Same budgets; standalone errors | Status and native fault regressions |
| Lease enforcement | Command lease and renewed deadline | Exact command/token binding | Poll signatures, deadlines, cancellation/lease negatives |
| Progress throttling | Single in-flight/coalesced/paced | Preserved; void events | Burst tests and repeated native event 429s |
| Diagnostic codes | Closed stages/codes | Preserved, terminal TLS/auth mapping | Frozen PR #53 contract and native completion assertions |
| Durable completion replay | Persist before send | Standalone implementation retained | Lost-response and fresh-process replay, no second ACK/event/snapshot |
| TLS/network restrictions | Monorepo transport | Stronger standalone connector retained | Existing HTTPS/DNS/address-family/security tests and routing fixture |
| Source Access | Existing policy guards | Unchanged | Full standalone policy/exclusion/diagnostics suite |
| Upgrade and rollback | Separate contracts | Existing guarded transaction | Installer models, Ubuntu runtime rollback and preservation acceptance |

### Native cases

All 24 scenarios exercise the real standalone runtime with signed requests,
exact lease bodies and a faulting synthetic control plane. They include healthy
and legacy boolean-only status, repeated progress 429s, one transient 429/502/503,
persistent 429/503, timeout, interrupted connection, invalid JSON/schema,
invalid/expired lease, authorization refusal, cancellation immediately after
dump, lost completion response, throwing journal callback, cancellation/lease
refusal/network failure during a genuinely running blocked mysqldump, cancellation
of running Restic, credential finalization failure and post-dump repository failure.

Successful cases verify one actual snapshot, extract its SQL with Restic and
compare byte length and SHA-256 with the Agent receipt. Every case restarts in a
fresh process and replays the exact persisted completion with no additional ACK
or execution event; successful snapshots are counted again to rule out duplicate
snapshots. Owned mysqldump/Restic/transport children are checked stopped, SQL and
credential workspaces removed, and secret values absent from diagnostic records.
The intentionally unremovable finalization fixture verifies a cleanup warning
and removes retained private test evidence only after restoring fixture access.

### Packaging adjustment

The first complete matrix passed Agent, contract and installer checks but failed
release packaging: the expanded source tar exceeds Node's default 1 MiB
`execFileSync` capture (`ENOBUFS`). The source archive helper now has an explicit
16 MiB ceiling. Its regression accepts a 2 MiB synthetic tracked source, rejects
an unknown revision and still refuses archives exceeding the ceiling. Clean
committed-source, immutable revision, hashes, reproducibility and activation
requirements remain unchanged. No installer/upgrade compatibility change is needed.

### Commands and evidence

The local matrix runs the existing `tests/ubuntu/Dockerfile` targets `validation`,
`network-routing` (including the private-loopback NET_ADMIN run) and
`runtime-upgrade` for **22.04 and 24.04**. Validation includes:

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm typecheck
pnpm build
pnpm test
pnpm test:contracts
pnpm validate:standalone
pnpm test:installers
pnpm package:release
# Repeat package:release, compare manifests, and verify SHA256SUMS.
```

Standalone tests preserve TLS/CA/hostname/expiry, address-family/DNS restrictions,
void ACK compatibility, mandatory completion/identity durability, Source Access,
exclusions, hooks and process-tree cancellation checks. Status regressions add
exact-token single-flight/deadlines, fresh signed attempts, no settled-result cache,
per-attempt/overall budgets and terminal TLS/refusal/body handling. Installer tests
retain all 70 upgrade/rollback checks, fresh/partial recovery and legacy refusal.

Native fixture reproduction (after building the validation image):

```sh
docker build --file tests/post-dump/Dockerfile \
  --build-arg TOOL_IMAGE=pluton-agent-validation:ci-22.04 \
  --tag pluton-agent-post-dump-port:local .
pwsh -File scripts/validate-post-dump.ps1
```

Repeat with the 24.04 validation tool image. The runner is unprivileged, read-only,
capability-free and shares only the disposable MySQL network namespace on an
internal network. It has no host ports, host data mounts or live credentials.
The validation workflow now runs this fixture after its existing Ubuntu targets.
**Hosted CI for the final commit remains pending** because this task does not push.

### Local results (2026-10-29)

| Check | Ubuntu 22.04 build | Ubuntu 24.04 build |
| --- | --- | --- |
| Frozen install, typecheck and build | PASS | PASS |
| Agent tests | 221 PASS, 0 skip | 221 PASS, 0 skip |
| Contract/fixture/packaging tests | 13 PASS, 0 skip | 13 PASS, 0 skip |
| Installer/downloader and upgrade/rollback | PASS, including 70 tests, 0 skip | PASS, including 70 tests, 0 skip |
| Fresh enrollment/heartbeat, partial recovery, legacy refusal | PASS | PASS |
| Standalone source-hash validation | PASS, 45 files, 27 explicit deltas | PASS, same contract |
| Reproducible release packaging and checksums | PASS, two matching manifests | PASS, two matching manifests |
| Private-loopback IPv4/IPv6 routing acceptance | PASS | PASS |
| Real-runtime upgrade, start-failure rollback and rename-gap recovery | PASS | PASS |
| Native MySQL/Restic fault/replay suite built from these artifacts | 24 PASS | 24 PASS |

The native runner uses pinned Oracle MySQL Linux userland with Node copied from
each Ubuntu validation image. These last two columns mean separately compiled
Ubuntu Agent artifacts, not a claim that Oracle MySQL ran on native Ubuntu VMs.
Runtime-upgrade acceptance covered the unchanged runtime/installer port before
the later packaging-only buffer adjustment; that helper is not in the upgrade
execution path. Workflow syntax passed offline `actionlint`. Diff hygiene and
changed-file credential/private-inventory review passed.

Security review found no weakened authentication, TLS, approval, rollback or
durability contract. The connector, HMAC/protocol, identity, Source Access policy,
upgrade guard/installers, lockfile and original extraction/golden vectors remain
unchanged. Independent-source hashes explicitly record the reviewed runtime/test
changes. Existing standalone `success:false` rejection stays terminal and maps to
authorization rejection at status checks; the monorepo's looser envelope handling
was not substituted. No arbitrary provider text enters the new diagnostics.

## Backend compatibility and operator upgrade

**Backend first, standalone Agent second.** Backend production must include PR #53
and accept the new closed completion diagnostics. A boolean-only status response
is readable; that does not make a pre-PR-53 backend compatible with new failure
metadata. The backend owns the atomic exact-lease renewal and cancellation state.
No backend change is included in this repository.

After approved review/merge and successful hosted checks:

1. Verify the deployed backend revision includes PR #53.
2. Pause the affected plan, drain/reconcile running and queued backup/Source
   Access work, and retain the previous reviewed Agent SHA/artifact.
3. In the existing host checkout (synthetic public example `/srv/pluton-agent`),
   require a clean tree, switch to `main`, fetch and fast-forward only to the
   reviewed approved commit. Verify its full SHA before invoking code as root.
4. Run `sudo bash upgrade-agent.sh --check`, then `sudo bash upgrade-agent.sh`.
   Do not run the fresh installer, supply an enrollment token, rotate identity
   or edit installation provenance. Current upgrade-protocol-v1 Agents use the
   existing hold/drain handshake; no unnecessary manual service stop is required.
5. Verify `systemctl is-active pluton-agent.service` and run the installed
   authenticated `check` command with the existing literal configuration/CA/roots,
   using the [upgrade guide](AGENT_UPGRADE.md). Check sends heartbeat only, no poll.
6. Keep plans paused until one explicitly authorized backup UAT is ready. Run
   Backup Now once; monitor dump completion, post-dump check, repository preparation,
   Restic snapshot, SQL byte/SHA-256 receipt and durable completion.
7. Verify intended source coverage and perform an isolated staged recovery with
   SQL hash/data checks. Keep existing recovery protection until independently
   accepted. Do not infer complete recovery from dump success alone.

If an older installation cannot acknowledge the hold, follow the separately
authorized drained/stopped-service procedure in [AGENT_UPGRADE.md](AGENT_UPGRADE.md).
Do not stop active work to bypass admission. No upgrade safeguard needs adjustment
for this port: root-owned hold/activity fence, clean checkout/provenance, pinned
private tools, transactional replacement and authenticated health checks remain.

The exact requested host checkout instructions are supplied in the private local
handoff, not committed as a production username/host inventory in this public repo.

## Rollback and remaining gates

Keep the durable upgrade ID, previous app/provenance and reviewed source commit.
Use `sudo bash upgrade-agent.sh --rollback <recorded-upgrade-id>` under separate
approval and normal drain. The upgrader checks identity, receipts, policy, config,
unit and backup digests before restoration. If legitimate state changed after the
upgrade, automatic rollback may refuse: retain evidence for review; do not erase
receipts, re-enroll, overwrite identity or rewrite provenance. Backend rollback is
a separate reviewed change and must not strand newer completion diagnostics.

Native systemd/cgroup behavior and deployed WAF routing/rate limits remain
production-only validation. Docker userland uses an explicit systemctl adapter;
the native MySQL/Restic tests use a synthetic authenticated control plane. No real
production deployment or historical incident-cause claim is made.

**Upgrade readiness:** ready for code review and hosted CI, then an approved
backend-first guarded standalone upgrade and one backup/recovery UAT. This is
not deployment approval. No production steps, push, merge or release publication
were performed.

## Exact changed-file inventory (25 files)

```text
.github/workflows/ci.yml
agent/src/backupFilesystem.ts
agent/src/backupLifecycle.ts
agent/src/client.test.ts
agent/src/client.ts
agent/src/commandStatus.test.ts
agent/src/commandStatus.ts
agent/src/lifecyclePolicy.ts
agent/src/lifecycleProcess.ts
agent/src/progressDelivery.ts
agent/src/runtime.ts
agent/src/transport.ts
contracts/post-dump-v1.json
contracts/standalone-source-v1.json
docs/AGENT_UPGRADE.md
docs/COMPATIBILITY.md
docs/POST_DUMP_BACKUP_RELIABILITY_PORT_REPORT.md
scripts/lib/source-archive.mjs
scripts/package-release.mjs
scripts/tests/post-dump-contract.test.mjs
scripts/tests/source-archive.test.mjs
scripts/validate-post-dump.ps1
tests/post-dump/Dockerfile
tests/post-dump/native.lab.ts
tests/post-dump/restart.mjs
```
