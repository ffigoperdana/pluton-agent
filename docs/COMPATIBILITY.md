# Versioned server/Agent contract

## OS and architecture matrix

| OS / architecture | Userland installation and regression validation | Native systemd / production acceptance |
| --- | --- | --- |
| Ubuntu Server 22.04 LTS x86_64 | TESTED: fresh install and complete container regression suite; [results](UBUNTU_VALIDATION.md) | Native boot/reboot/cgroup enforcement pending |
| Ubuntu Server 24.04 LTS x86_64 | TESTED: pinned 24.04.5 container userland, fresh install and complete suite | Full native support pending [booted VM acceptance](NATIVE_SYSTEMD_ACCEPTANCE.md), including exact 24.04.5 Server image |
| Other Ubuntu releases / Debian / derivatives | Unsupported; fresh installer refuses | No claim |
| ARM64 / other architectures / non-systemd / cgroup v1 | Unsupported | No claim |

Both installer target releases require the pinned private Linux x64 toolchain,
native systemd and unified cgroup v2. Container tests share Docker's kernel and
simulate systemctl activation; they establish userland evidence only. App-only
upgrade is not an OS upgrade or a monorepo migration.

## Versioned protocol

The initial extraction preserved the 36 Agent TypeScript source files from the
Pluton Server commit in `contracts/extraction-source.json`. Subsequent independent
[HTTPS/enrollment changes](NETWORK_ENROLLMENT.md) use the explicit hash delta
`contracts/standalone-source-v1.json`; original extraction hashes and server
golden vectors remain unchanged. The current Agent advertises 0.8.0; original
0.7.0 HMAC/exclusion vectors remain authoritative and the 0.8.0 S3 vectors are
additive (see the S3 section below).
The server need not import this repository to run its production backend.

The [post-dump reliability port](POST_DUMP_BACKUP_RELIABILITY_PORT_REPORT.md)
requires backend PR [#53](https://github.com/ffigoperdana/pluton/pull/53), merge
`edcfe5fba3a2eb47730307fa53c90730177b5430`, **before** the Agent upgrade. The
backend must accept the new closed status/finalization completion diagnostics.
Request HMAC, exact lease binding, void ACK/events/completion responses, identity
and durable receipt schemas are unchanged. Status may supply `leaseExpiresAt`;
legacy boolean-only cancellation results remain compatible under the existing
authenticated 60-second renewal contract. Failed/malformed authorization checks
never permit repository work. Only status retries transient 429/5xx/network or
timeouts; TLS and authorization refusals remain terminal.

| Pairing/function                        | Status and boundary                                                                                                                             |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Agent 0.7.0 + extracted server revision | Protocol/HMAC/exclusion golden vectors checked; synthetic TLS enrollment/heartbeat tested on Ubuntu; real deployed pairing NOT TESTED           |
| Agent 0.8.0 + stage 1 server            | Sealing vector (`contracts/v0.8.0.json`) checked on both sides; Agent side tested against synthetic SFTP and S3 fixtures; real deployed pairing NOT TESTED |
| Server-Managed Source Access            | Existing host delegation, modes/version 1, revision/apply/lease/receipt checks preserved; server must support them                              |
| Filesystem envelopes 1–5                | 1–4 unchanged and SFTP-only; 5 adds S3 and sealed secrets for Agents that advertise `backupPayloadVersion: 5`; unknown versions/fields refuse |
| Database/hooks lifecycle versions 1/2   | Existing engines, multiple DB limits, root-owned tools and constrained hooks unchanged; real DB integration NOT TESTED by the synthetic fixture |
| Older server or Agent                   | Capability/version negotiation remains required; no claim that every historic release is supported                                              |
| Existing monorepo-installed Agent       | Ordinary upgrade REFUSED; explicit `--migrate-monorepo` transaction ([guide](MONOREPO_MIGRATION.md)): exact provenance, same drain/health/rollback   |
| Existing standalone installation        | App-only upgrade/rollback with its own committed source and distribution marker; real systemd lifecycle NOT TESTED locally                      |
| Server replication/recovery             | Remains server-only; the Agent receives the S3 key of its own S3-primary plans only; never replica keys or Internal root privileges |
| ARM64/non-systemd/custom layout         | UNSUPPORTED for these installer/upgrade contracts                                                                                               |

`contracts/v0.7.0.json` contains synthetic **server-generated** HMAC canonical
request/command vectors and exclusion acceptance/normalization/Restic anchoring
results. They were generated from actual pinned server functions, not a rewritten
signer or an invented API. `contracts/extraction-source.json` pins normalized source
hashes for the Agent and the original server definitions. Standalone CI verifies
these fixtures against actual compiled Agent functions, mutation/expiry negatives,
version rejection and source parity without loading server code.

The JSON contracts are portable data. A server-side test can independently consume
the same immutable file and assert its actual `signAgentRequest`,
`signAgentCommand`, `parseBackupExclusions` and `sourceResticExclusions` outputs.
The separate monorepo migration plan requires wiring that conformance check into
server CI before deleting cross-repository tests. Current backend parity tests
and their Agent source remain intact in the original repository. No silent
replacement with a new protocol/package was performed.

An optional read-only maintainer check automates this against a separately
provided, reviewed server checkout (not used during Agent build/install):

```sh
node scripts/verify-server-contract.mjs --server /path/to/reviewed/server-checkout
```

It verifies the exact server revision and contract source hashes, evaluates the
actual pure server functions with the pinned compiler and checks the same golden
vectors. An absent server does not affect normal Agent CI/build/install. Server
CI adoption of that check is a separately reviewed change, not silently installed
into the original repository by this task.

For future changes, version and review contract updates explicitly, generate new
vectors from the authoritative implementations, retain old compatibility fixtures
and test negative boundaries. Do not casually edit expected signatures or drop
the extraction parity guard to hide drift. Source parity is an initial extraction
gate; subsequent independent development requires a reviewed new baseline/version.

Capabilities alone do not authorize a path, hook, DB or operation. Current server
checks remain authoritative for admissions and unsupported exclusions; the Agent
revalidates signed versioned payloads and effective host policy at execution.
Do not send an unsupported request and assume ignored fields are safe.

## S3 repositories (contract `pluton-agent-0.8.0`)

Agent 0.8.0 adds two optional inventory capability fields:
`repositoryBackends: ["sftp", "s3"]` and `backupPayloadVersion: 5`. The Pluton
server validates the inventory with a strict schema, so a server without stage 1
S3 support **refuses the 0.8.0 enrollment and heartbeat**. Deploy the compatible
server first, then install or upgrade Agents; roll back in the reverse order,
Agent first, then server.

`BACKUP_FILESYSTEM` payload version 5 may name `rclone.type` `sftp` or `s3`. Every
secret (repository password, SFTP `pass`, S3 `access_key_id` and
`secret_access_key`, and every database password, sealed as `lifecycle.database`
for lifecycle shape 1 or under its `databaseId` in `lifecycle.databases`) is
inside `sealed`; the plain lifecycle carries no `password`. The Agent restores
each database password into its entry before use and refuses a payload with a
plain database password, a database without a sealed password or a sealed
password without a database. Sealing uses HKDF-SHA256 over the per-Agent secret
with info `pluton-agent-command-secrets-v1`, AES-256-GCM with a 12-byte nonce and
16-byte tag, and additional data made of that label, the command ID and the lease
token separated by newlines. Plain options never contain those keys; such a
payload is refused. The command HMAC still covers the whole payload. Versions 1
to 4 are unchanged and SFTP-only; an Agent that does not advertise version 5 keeps
receiving them.

Version 5 keeps the source rules of the version the server would otherwise send:
the version 4 exclusion grammar, the pre-backup scan only when exclusions are
present, and version 3 source binding and receipt recovery when the lifecycle is
version 2.

`contracts/v0.8.0.json` holds the synthetic heartbeat request, a signed version 5
S3 command and the sealing vector copied verbatim from the approved design; the
server test suite uses the same sealing vector.
