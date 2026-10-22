# HTTPS connectivity, enrollment diagnostics and partial recovery

This independently developed change starts from reviewed standalone main
`095088beeb3a10dc5fdda4f55db07fa4d17240be`. It preserves Agent capability/wire
version **0.7.0**, HTTPS verification, enrollment/HMAC payloads, Source Access,
host delegation, exclusions, cancellation and upgrade admission. No production
host, DNS, proxy, token, policy, storage or service is changed by this work.

## Evidence and root-cause limits

The reported host resolves both families and already has Node 22.18.0 network
autoselection enabled with a 250 ms attempt timeout. Its explicit IPv4 HTTPS
probe succeeds while automatic selection times out. This establishes a Node
connection-selection/path difference; it does not establish broken IPv6, an
invalid token, DNS failure or a proxy configuration fault. No production endpoint
was contacted to investigate it.

An isolated Linux traffic-control fixture reproduces a matching failure with
**either family**: delay a viable first address's TCP SYN by 600 ms, leave the
other family's listener unreachable, and compare Node's native 250 ms sequential
autoselection with an explicit family. Autoselection fails, while explicit family
and the new transport succeed. This proves a concrete cancellation/timing
mechanism, not the cause on the reported host. It is also possible for a connected
TCP path to stall during TLS; separate loopback fixtures cover that case.

Node's supported behavior and the underlying socket/TLS APIs were reviewed
against the pinned [Node 22.18.0 net documentation](https://nodejs.org/download/release/v22.18.0/docs/api/net.html)
and [HTTPS documentation](https://nodejs.org/download/release/v22.18.0/docs/api/https.html).
The source fixture, rather than a DNS-family ordering assumption, provides the
reproduction evidence. Real production SYN timing, routes, MTU, packet loss,
firewall/proxy behavior and DNS latency remain unmeasured.

## Connection behavior and security

The Agent resolves through the system resolver, retains its ordering within each
family, alternates families, deduplicates addresses and considers at most 16
candidates. A new TCP/verified TLS connection starts every 250 ms while earlier
viable attempts remain alive. It uses supported `net.createConnection` and
`tls.connect`; it does not set process-wide DNS/network defaults or force IPv4.

DNS has a 15-second promise deadline; each candidate's TCP/TLS handshake has a
5-second deadline; the full DNS/connect/HTTP response operation has a 30-second
deadline. DNS consumes that total budget: it does not add another 15 seconds or
restart the deadline when HTTP begins. The 250 ms family stagger is unchanged.
This tolerates slow but successful lookups while bounding a stuck request; failure
can now take longer to report than with the former 3-second DNS/10-second total
limits. Outstanding sockets/timers are destroyed on success or failure. Native
`getaddrinfo` work cannot be cancelled by Node's lookup API; a late resolver
callback is ignored after the request promise times out. The system resolver
itself must still be healthy; these deadlines are not an OS resolver repair.

The standalone upgrader retains its separate bounded health-process deadline.
Process startup and inventory work consume that outer allowance; increasing the
transport budget does not extend it or relax upgrade health/rollback admission.

Only one verified winning socket is handed to a private single-use HTTP Agent.
HTTP headers, enrollment tokens and signed bodies are sent **once**, after
connection selection. Losing candidates receive no HTTP credentials. No automatic
HTTP retry occurs after a send, timeout, reset, HTTP error or ambiguous enrollment.
Pooling is intentionally disabled for this connection-selection boundary.

Every HTTPS candidate retains the original origin's SNI and hostname verification,
trusted CA and optional configured mTLS material. Certificate verification errors
before a winner are terminal. Responses are bounded to 2 MiB, deadlines include
the response body, invalid JSON/envelopes fail closed, redirects are not followed,
and cross-origin request paths refuse. Existing explicit trusted-LAN HTTP opt-in
remains available for its original test/operational contract; HTTPS never falls
back to HTTP. The network diagnostic itself requires HTTPS.

## Safe failure output

Only fixed classifications and bounded HTTP status numbers are exposed:

| Diagnostic | Meaning / next investigation |
| --- | --- |
| DNS resolution failed / timed out | Check the host resolver/NSS path and DNS latency. A forced-family probe can also have no A/AAAA records for that family. No server-side token decision is known. |
| TCP connection failed | No usable candidate connected; inspect egress/routes/firewall through approved diagnostics. |
| TCP/TLS connection timed out | Candidate connection/handshake budget expired; distinguish SYN timing from TLS progress in approved private evidence. |
| TLS verification failed | Check approved CA, hostname, certificate validity and clock; never disable verification. |
| Server returned HTTP 400/401/403/429/5xx | An HTTP peer responded. Status alone does not identify a token, WAF, rate-limit or server-contract fault. |
| Request timed out / connection interrupted | The HTTP outcome can be ambiguous after bytes were sent. Do not automatically enroll again. |
| Invalid server response / response exceeded size limit | Invalid JSON, malformed enrollment envelope or excessive response; retain safe status and review server compatibility. |
| Enrollment rejected | A successful HTTP response carried `success:false`; arbitrary server error text is suppressed. |
| Existing identity or enrollment state requires operator review | Enrollment will not replace an identity or run concurrently with an existing enrollment lock. |

Tokens, identity secrets, Authorization/HMAC headers, keys, request bodies,
arbitrary upstream bodies and nested exception messages are never included in
these classifications. A successful `{}` probe returning HTTP 400 proves HTTP
reachability only; it is not evidence that a real enrollment token is invalid.

## Read-only preflight: local versus network

`bash install-agent.sh --check --server https://server.example.internal
--allowed-root /srv/example-app` keeps its original meaning: local prerequisites,
no network, token, identity or filesystem writes. It does not acquire/download a
runtime. A clean machine without a trusted Node runtime cannot gain an actual
Node network test while also remaining strictly read-only.

For an approved private Node 22.18.0 and a build of this reviewed source, run:

```sh
/opt/pluton-agent/runtime/bin/node agent/dist/index.js network-check \
  --server https://server.example.internal
```

Add `--ca-file /absolute/approved-ca.pem` where required. Use the **new source's**
compiled CLI or a verified installation containing this change; an old installed
CLI does not implement `network-check`. No credentials or identity arguments are
accepted. The command sends three unauthenticated `GET /api/health` probes:
automatic dual-family, IPv4-only, IPv6-only. The command reports the shared
15-second DNS deadline within a 30-second total budget per probe; the sequence can
take up to about 90 seconds, excluding delayed OS resolver work and scheduling.
It never enrolls, loads an Agent identity, sends a heartbeat or polls commands.
Configured mTLS material, if explicitly supplied through the approved Agent
environment, is still used for the TLS handshake.

Exit success means the automatic path reached a verified HTTPS endpoint with a
2xx JSON response. A single-family failure does not fail a working automatic
path. This is connectivity evidence, not health-payload/production Server or
backup/recovery acceptance. A health-endpoint 404/403 can coexist with a working
enrollment route; no token is sent to test that assumption. If curl succeeds and
Node fails, compare these Node family results, CA trust and fixed error category;
do not disable IPv6, edit global DNS, hardcode CDN addresses or relax TLS.

When using an existing partial install's private runtime, first run the protected
recovery `--check` below to validate its ownership and recorded tree integrity.
Building the reviewed source is a separate explicit preparation step that writes
only generated build/dependency files in the checkout. Use its scoped private
runtime PATH and pinned Corepack/pnpm, not system/global package installation:

```sh
(
  set -euo pipefail
  export PATH="/opt/pluton-agent/runtime/bin:$PATH"
  corepack=/opt/pluton-agent/runtime/lib/node_modules/corepack/dist/corepack.js
  node "$corepack" pnpm install --frozen-lockfile --ignore-scripts
  node "$corepack" pnpm build
)
```

Review the immutable checkout before executing its compiler/CLI. Nothing here
authorizes copying compiled output over an enrolled installation.

## Failed first installation: preserve, inspect, quarantine

Fresh installation, partial failed installation and an enrolled Agent remain
distinct. The normal installer still refuses existing app/config/state/unit paths.
It does not automatically purge or replace them after an enrollment failure.

1. Stop retrying enrollment. Retain the safe failure stage/status. A lost response
   can mean the Server consumed the token even when no identity file was saved.
   Inspect the Server's enrollment/device outcome through an authorized operator;
   do not assume token failure, revoke devices or change tokens as a workaround.
2. From this reviewed source, run:

   ```sh
   sudo bash recover-agent-install.sh --check
   ```

   This is local/read-only and requires root only to inspect protected files.
   It verifies standalone format=1 provenance and the Node/Restic/rclone pins,
   root ownership/protected ancestors,
   the original SHA-256 tree, private config, an **empty** service-owned 0700 state
   directory, no service unit/loaded service and no running service-account process.
   ANY identity, hidden/temp file, receipt, policy, lock, transaction evidence,
   symlink, integrity mismatch or nonstandard layout refuses recovery.
3. Only when the Server outcome has been independently confirmed **unenrolled**,
   explicitly quarantine the eligible partial install:

   ```sh
   sudo bash recover-agent-install.sh --quarantine --confirm-unenrolled
   ```

   This is not read-only. It moves only the verified private app/config/empty
   state into a root-owned 0700 `pluton-agent-partial.*` directory under `/var/lib`.
   Config stays 0600. Same-filesystem renames are required and synced; cross-device
   copies refuse. No file is deleted, no source root or application data is moved,
   no server request occurs, and no service is stopped/restarted/reloaded. If a
   move/sync fails, stop and retain both original and reported quarantine paths;
   the three moves are not a single atomic transaction. Do not delete evidence
   or manually merge it into a later installation.
4. Review/test the corrected immutable commit, confirm connectivity and run the
   **normal** fresh-install command with explicit approved roots and a Server-
   approved unconsumed enrollment token at the private prompt. The existing
   installer guards still apply; no force or migration bypass was added.

The helper cannot prove remote enrollment absence; the explicit confirmation is
an operator assertion, never an automated inference from a missing local identity.
If a valid identity, partial identity write, enrollment lock or remote enrolled
device exists, stop for separately reviewed state-preserving recovery. This helper
does not recover a lost Server-issued secret and does not adopt monorepo Agents.

## Source provenance and versioning

The original `contracts/extraction-source.json` remains unchanged. Versioned
`contracts/standalone-source-v1.json` explicitly lists changed/new runtime and test
files, their extraction hashes where applicable, new hashes and reasons against
reviewed base `095088b`. Standalone validation checks that delta, all source files
and import boundaries; unrecorded edits/additions and extraction-manifest drift
fail. No accepted installed provenance record is rewritten to hide a mismatch.
Server-generated protocol/HMAC/exclusion vectors and dependency/tool pins remain
unchanged. Runtime source is now independently developed and is no longer claimed
to be wholly byte-identical to extraction.

No capability/protocol version change is required. Agent 0.7.0 source deliveries
are distinguished by their immutable commit. Existing generated install commands
that pin the older commit **must be regenerated or repinned after review** to
obtain this fix. Entry point/HTTPS URL/roots/Server-Managed Source Access remain
the same. The separate Server repository/UI is not modified by this task; never
reuse an immutable release tag/asset for different bytes.

## Validation

Initial dual-stack validation on **2026-10-22**, using private Node **22.18.0**, pnpm
**10.20.0**, the unchanged frozen minimal lock and isolated synthetic servers:

| Check | Ubuntu 22.04 x86_64 | Ubuntu 24.04 x86_64 |
| --- | --- | --- |
| Frozen dependencies, typecheck/build, private installation, verified TLS/HMAC enrollment/heartbeat | PASS | PASS |
| All Agent unit/integration tests | 172 PASS, 0 FAIL, 0 SKIP | 172 PASS, 0 FAIL, 0 SKIP |
| Golden contracts, source-baseline negatives, docs/release/fixture tests | 8 PASS, 0 FAIL, 0 SKIP | 8 PASS, 0 FAIL, 0 SKIP |
| Installer failure/reuse/refusal/recovery safety models | PASS | PASS |
| Actual protected app/config/empty-state check and synced private quarantine/restoration | PASS; adapted manager | PASS; adapted manager |
| Upgrade/rollback/provenance/durability/locale tests | 62 PASS, 0 FAIL, 0 SKIP | 62 PASS, 0 FAIL, 0 SKIP |
| C, C.UTF-8, real privately generated en_US.UTF-8 integrity | PASS | PASS |
| Native Node 250 ms cancellation reproduced with delayed IPv4 AND IPv6 SYN | PASS | PASS |
| Explicit family and new retained parallel connection complete with one POST | PASS both families | PASS both families |
| Standalone boundary, Bash syntax and reproducible release packaging twice / checksums | PASS | PASS |
| Native booted systemd/cgroup/VM / production network or Server pairing | PENDING | PENDING |

Workflow actionlint and diff/privacy-pattern checks passed. Final fixed-code
diagnostic/source-delta checks and recovery metadata-pin refusal/private quarantine
also passed again on both OS versions. Packaging manifests bind the fixture's synthetic Git commit;
these are deterministic packaging regressions, not published final-commit release
artifacts. Generated certificates, state, logs, archives and downloads remain
ignored/in disposable images. No production credentials or infrastructure details
are committed.

Tests cover both
families, stalled and unreachable candidates, DNS failure/latency, connection and
request deadlines, certificate/hostname rejection, HTTP status, malformed/large/
interrupted responses, redaction, one-send enrollment, identity preservation,
read-only GET preflight and guarded quarantine. Existing protocol, filesystem,
database/hooks, exclusions, locale, installer and upgrade/rollback tests remain.

The additional routing target is explicit:

```sh
docker build --platform linux/amd64 --target network-routing \
  --build-arg UBUNTU_VERSION=24.04 -f tests/ubuntu/Dockerfile \
  -t pluton-agent-routing:local .
docker run --rm --network none --cap-add NET_ADMIN pluton-agent-routing:local
```

Repeat with 22.04. NET_ADMIN applies only to disposable loopback in a private
network namespace; never use host networking, mounts or privileged mode. Root
recovery file/permission/digest/quarantine checks run in disposable images with
explicitly adapted systemctl queries; the real systemctl binary is restored after
that fixture. This is not native service-manager acceptance. Native booted VM,
production routing/proxy cause, current deployed Server pairing and real DB/SFTP
recovery remain **PENDING / NOT TESTED**. No push, deployment or production action
is performed here.

## Slow DNS budget evaluation

The 15-second DNS / 30-second total defaults improve tolerance for slow successful
resolution. They do not establish the cause of a production connectivity failure.
Regression coverage uses a synthetic resolver and private loopback HTTPS:

- A real 10.1-second delayed lookup crosses both former limits and still completes
  one verified enrollment POST after falling back from unreachable IPv6 to IPv4.
- A controlled clock keeps unresolved DNS pending at 14,999 ms and rejects at
  15,000 ms. A late successful callback cannot dispatch enrollment.
- With 12 seconds spent resolving, an incomplete enrollment response remains
  pending at total 29,999 ms and expires at 30,000 ms, rather than receiving a
  fresh HTTP allowance. The server sees one POST; operator output contains only
  the fixed timeout category, without the synthetic token or partial response.
- Mutating each default back to its former 3-second DNS or 10-second total value
  causes its corresponding regression to fail. These mutations run only inside
  disposable containers and are never part of delivered source.
- Existing two-way IPv4/IPv6 fallback, stalled TLS candidates, CA/hostname
  rejection, HTTP/body redaction, enrollment state and no-replay tests remain.

`network-check` uses the same transport defaults and reports the per-probe and
three-probe budgets. Its regression also delays the automatic probe's resolver
by 10.1 seconds and requires all three probes to succeed with only unauthenticated
health GETs, no identity access, and HTTPS verification. Agent 0.7.0 protocol vectors,
dependency pins, installation admission and source verification are unchanged.

Slow-DNS follow-up validation on **2026-10-22**, with Node **22.18.0** and pnpm
**10.20.0**, passed on both Ubuntu **22.04** and **24.04** synthetic x86_64 userlands:
**175 Agent tests, 8 contract tests and 62 upgrade tests per OS, zero failures or
skips**. Fresh installation, installer safety, protected recovery, frozen build,
source-delta verification and twice-generated release checksums also passed.
The strengthened final DNS/diagnostic tests, all Agent/contracts and packaging
were checked again in matching cached disposable userlands. Isolated SYN-delay
acceptance passed for both IPv4 and IPv6 on each OS with the final runtime source.
No archives were published. Systemd calls used the explicit fixture adapter;
native booted VM, production DNS/routing and real Server pairing remain untested.

## Changed files

- `agent/src/network.ts`, `transport.ts`, `client.ts`, `errors.ts`: bounded
  pre-dispatch connection racing, response admission and safe categories.
- `agent/src/networkPreflight.ts`, `index.ts`, `identity.ts`: explicit read-only
  health probes, enrollment serialization and exclusive durable identity creation.
- `agent/src/transport.test.ts`, `enrollmentState.test.ts`, `errors.test.ts`:
  real loopback TLS/HTTP fixtures, timeouts, redaction and state preservation.
- `recover-agent-install.sh`, `installers/recover-agent-install.sh`,
  `installers/lib/recover-partial.sh`: guarded read-only inspection/private quarantine.
- `installers/tests/install-agent.test.sh`, `tests/ubuntu/partial-recovery.sh`:
  negative safety models and actual disposable file/permission/integrity checks.
- `tests/ubuntu/network-routing.mjs`, `tests/ubuntu/Dockerfile`,
  `tests/ubuntu/systemctl-fixture.sh`, `.github/workflows/ci.yml`: two-version
  regression matrix, labelled manager adapter and isolated SYN-delay acceptance.
- `contracts/standalone-source-v1.json`, `scripts/validate-standalone.mjs`,
  `scripts/tests/source-baseline.test.mjs`: explicit source delta and negative drift checks.
- `README.md`, `docs/OPERATIONS.md`, `docs/COMPATIBILITY.md`,
  `docs/EXTRACTION_AUDIT.md`, `docs/RELEASES.md`, `docs/UBUNTU_VALIDATION.md`,
  `docs/NETWORK_ENROLLMENT.md`: operator procedures, provenance and honest evidence boundaries.
