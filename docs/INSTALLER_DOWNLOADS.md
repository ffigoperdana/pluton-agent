# Dependency download failures and safe fresh installation

This records the earlier downloader patch against Node 22.18.0. The subsequent
[Node 22.23.4 security patch](NODE_RUNTIME_SECURITY.md) retains the downloader's
GET-only retry bounds and adds the reviewed Node archive SHA-256 pin.

This change affects the source installer and its GET-only dependency downloader.
Agent protocol/capability **0.7.0**, Node **22.18.0**, pnpm **10.20.0**, Restic
**0.19.1**, rclone **1.75.1**, the frozen lockfile and existing SHA-256 pins remain
unchanged. No production Agent or service is changed by validation.

## Audit findings

The previous installer issued one unbounded curl invocation per archive/index.
A transient DNS error for GitHub could abort Restic acquisition after Node had
already downloaded. The installer had already created the service account and
`/var/lib/pluton-agent`; although its exit trap removed application staging, that
empty final state directory correctly caused the next fresh-install guard to
refuse. The original recovery helper required a verified app/config pair, so it
could not admit this earlier empty-state-only failure shape.

## Bounded dependency GET acquisition

`installers/lib/dependency-download.sh` accepts only four named artifacts: the
pinned Node archive, its version-specific checksum index, Restic and rclone. It
cannot accept an Agent URL, token, request body, header or arbitrary download URL.

Each artifact has at most **4 attempts**, backoff **2 / 4 / 8 seconds**, a
**30-second connection timeout** (including DNS/TLS), at most **120 seconds per
transfer**, and a shared **300-second total budget**, including backoff. The last
transfer allowance is reduced to the remaining budget. Limits are subject to OS
scheduling and curl's resolver implementation; this does not repair host DNS.

Retries cover curl DNS failures (5/6), connect/partial/empty/reset/send/receive and
HTTP/2 stream failures (7/18/52/55/56/92), timeout (28), and temporary HTTP statuses
408/429/500/502/503/504. Permanent HTTP errors, local write failures, certificate or
TLS configuration failures and checksum mismatches stop immediately. Logs show
only the artifact label, fixed failure category, bounded status and retry timing;
raw curl/proxy diagnostics are suppressed to avoid exposing private information.

Every transfer is an explicit GET. User curl configuration is disabled before any
other curl option, so a `.curlrc` cannot inject POST/authentication or insecure
TLS. Original and redirected protocols are restricted to HTTPS, with at most five
redirects and TLS 1.2 or newer. CA/hostname verification remains enabled. There is
no forced IP family, hardcoded CDN address, HTTP downgrade or insecure fallback.
The normal trust store, approved CA-bundle environment and proxy environment
remain available; settings in `.curlrc` are intentionally ignored.
See the [curl option documentation](https://curl.se/docs/manpage.html).

Failed `.part` files are removed; retries start from byte zero. A completed file
is renamed within private staging and still **must pass SHA-256 verification
before extraction or execution**. Restic/rclone retain their embedded hashes.
Node retains the version-specific HTTPS checksum-index trust model; this change
does not claim a new detached-signature or embedded Node digest check.

This helper is never used for enrollment, health/heartbeat, signed requests or
other Agent traffic. **Enrollment is sent once and is never automatically
retried**, including when the server may have consumed a token before a lost
response. Agent transport DNS/request budgets remain separately documented in
[network and enrollment diagnostics](NETWORK_ENROLLMENT.md).

## Failure boundary and operator recovery

Downloads, verification and source build now finish in a root-private staging
tree **before** service-account/state creation. Temporary archives, extraction,
build homes and package caches live under that tree and are removed on normal
failure. A failed initial download/build leaves no final app, configuration,
state directory or unit. The fresh guard is checked again after preparation;
state-directory creation is exclusive and never adopts an existing directory.
An application that appeared during preparation is refused, not replaced.
Service absence is checked before preparation and activation, including packaged,
runtime and loaded/transient units. Unknown manager state refuses. The fresh path
never stops/restarts an existing service; it starts the new unit after enrollment.
The gate requires explicit `LoadState=not-found`, `ActiveState=inactive` and
`MainPID=0`, using property output rather than assuming any nonzero exit means
absence; see upstream [systemd 249](https://github.com/systemd/systemd/blob/v249/src/systemctl/systemctl-show.c)
and [255](https://github.com/systemd/systemd/blob/v255/src/systemctl/systemctl-show.c).

After a reported pre-activation failure, correct DNS/network trust and review the
immutable source before a new fresh attempt. No enrollment credential has been
sent at that point. Do not use `--force`, purge paths, remove identity files or
edit provenance to bypass a refusal. Interrupted power/SIGKILL can leave private
staging; it is never reused or automatically swept. Unknown transaction remnants
require operator review.

For old partial installations or a later failure, preserve all residual files and
run the local read-only check from this reviewed source:

```sh
sudo bash recover-agent-install.sh --check
```

Two shapes are eligible: verified standalone app/config plus empty state, or
**only** an empty service-owned 0700 state directory with app/config completely
absent. Both require protected ancestors, same-filesystem quarantine, no service
definition/loaded service and no service-account process. The app/config shape
additionally requires all original provenance, version, ownership, permission and
SHA-256 checks. An unverified app is never treated as an empty-state-only install.

ANY identity, dangling identity link, hidden/temp file, receipt, policy or
enrollment lock refuses. No existing identity/state is deleted or reset. A failed
check preserves files and requires separate review. After independently confirming
the host was **not enrolled** on the server, an operator may explicitly run:

```sh
sudo bash recover-agent-install.sh --quarantine --confirm-unenrolled
```

This moves only the validated paths into a root-owned 0700 directory under
`/var/lib`. For empty-state-only recovery it moves just the empty state directory.
It never deletes evidence, sends a server request, or stops/restarts/reloads a
service. The confirmation cannot be inferred automatically from a missing local
identity. See the [full recovery procedure](NETWORK_ENROLLMENT.md).

## Regression scope

Tests exercise temporary DNS failure then recovery, time/count/backoff limits,
interrupted download replacement, wrong checksums before extraction, GET-only
admission, secret-safe output, existing-Agent refusal and both recovery shapes.
Retry error codes/backoff and elapsed-budget boundaries use injected curl faults
and a controlled clock, without waiting five minutes per failure case.
Real curl loopback HTTPS tests cover an interrupted body, untrusted CA, wrong
hostname, HTTPS-to-HTTP redirect refusal and hostile `.curlrc` settings.

The Ubuntu fixture first performs actual verified Node acquisition followed by
four injected Restic DNS failures, and requires no final app/config/state/unit or
account plus a passing fresh preflight. It then completes the normal pinned
source install and synthetic TLS enrollment/heartbeat. Root recovery tests verify
legacy empty-state quarantine and preservation of hidden enrollment evidence.
Systemd lifecycle calls use the explicit disposable adapter; this is not native
booted-systemd acceptance or a production Server/network test.

## Validation results

Local validation on **2026-10-22** used private Node **22.18.0**, pnpm **10.20.0**,
the unchanged frozen lockfile and disposable x86_64 Ubuntu userlands:

| Check | Ubuntu 22.04 | Ubuntu 24.04 |
| --- | --- | --- |
| Node succeeds / four injected Restic DNS failures / no final state or account / fresh preflight | PASS | PASS |
| Real pinned fresh install, private TLS enrollment and signed 0.7.0 heartbeat, no polls | PASS | PASS |
| Downloader faults, real curl TLS/partial/redirect/curlrc tests, existing/loaded-Agent refusal | PASS | PASS |
| Root-protected empty-state-only and verified app/config quarantine; identity/evidence refusal | PASS | PASS |
| Agent unit/integration tests | 175 PASS, 0 FAIL, 0 SKIP | 175 PASS, 0 FAIL, 0 SKIP |
| Contracts/source-baseline/release/docs fixtures | 8 PASS, 0 FAIL, 0 SKIP | 8 PASS, 0 FAIL, 0 SKIP |
| Upgrade/rollback/provenance/locale tests | 62 PASS, 0 FAIL, 0 SKIP | 62 PASS, 0 FAIL, 0 SKIP |
| Frozen build/typecheck, standalone boundary, Bash syntax, packaging twice and SHA-256 verification | PASS | PASS |
| Native systemd/cgroup booted VM / production DNS or Server pairing | NOT TESTED | NOT TESTED |

Packaging binds each disposable fixture's synthetic Git commit and produces only
local reproducibility/checksum evidence, not a published release. No push,
deployment, real Agent access or real service restart was performed. Generated
archives, certificates, identities and raw logs remain ignored/in disposable tests.
