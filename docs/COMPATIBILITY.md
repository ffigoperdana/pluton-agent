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

This extraction preserves the 36 Agent TypeScript source files from Pluton Server
source commit recorded in `contracts/extraction-source.json`; no runtime wire or
security behavior changed. Package metadata now agrees with advertised Agent
0.7.0. The server need not import this repository to run its production backend.

| Pairing/function                        | Status and boundary                                                                                                                             |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Agent 0.7.0 + extracted server revision | Protocol/HMAC/exclusion golden vectors checked; synthetic TLS enrollment/heartbeat tested on Ubuntu; real deployed pairing NOT TESTED           |
| Server-Managed Source Access            | Existing host delegation, modes/version 1, revision/apply/lease/receipt checks preserved; server must support them                              |
| Filesystem envelopes 1–4                | Existing parser retained; v4 for exclusions; unknown versions/fields refuse                                                                     |
| Database/hooks lifecycle versions 1/2   | Existing engines, multiple DB limits, root-owned tools and constrained hooks unchanged; real DB integration NOT TESTED by the synthetic fixture |
| Older server or Agent                   | Capability/version negotiation remains required; no claim that every historic release is supported                                              |
| Existing monorepo-installed Agent       | Standalone upgrade REFUSED; separate state-preserving migration approval required                                                               |
| Existing standalone installation        | App-only upgrade/rollback with its own committed source and distribution marker; real systemd lifecycle NOT TESTED locally                      |
| Server replication/recovery             | Remains server-only; Agent receives no S3 replica key or Internal root privileges                                                               |
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
