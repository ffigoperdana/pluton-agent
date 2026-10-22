# Ubuntu compatibility audit and validation

Baseline: reviewed local `main`/`origin/main`
`8ee7536e7cbbdab06f7a0a0f470c70d21291daf4`. This work uses only disposable
synthetic installations. No production host, Agent, token, policy, server checkout
or storage is required. Agent capability/protocol version remains **0.7.0**.

## Verdict and evidence boundaries

Ubuntu 22.04 remains tested, and Ubuntu 24.04 passes the isolated userland matrix
below. Full native support remains pending booted-VM acceptance. A successful
container build cannot certify a Server ISO,
kernel, AppArmor profile, boot behavior or cgroup controller enforcement. In
particular, the 24.04 image's `VERSION_ID=24.04` does not certify the requested
**24.04.5 Server ISO**. Record that exact ISO/cloud-image digest and point release
in the [native acceptance record](NATIVE_SYSTEMD_ACCEPTANCE.md).

See the final results table below for actual execution status. Hosted CI has not
been dispatched by this local task. Historical extraction results in
[the extraction audit](EXTRACTION_AUDIT.md) are not new test executions.

## Source audit

| Area | Ubuntu 22.04 / 24.04 difference or finding | Decision and validation |
| --- | --- | --- |
| OS identification | Installer previously accepted arbitrary Debian derivatives and versions, despite only a 22.04 fixture | Explicit `ID=ubuntu`, `VERSION_ID=22.04/24.04` allowlist; other releases/derivatives rejected. No `ID_LIKE` fallback. |
| Architecture | All private binary pins are Linux x64 | x86_64 only; both builds force `linux/amd64`; ARM64 remains unsupported. |
| systemd | Jammy 249 versus Noble 255; container adapter previously printed 249 for every OS | Adapter now reports the installed systemd version and labels simulated lifecycle. Real `systemd-analyze verify` parses the generated unit. Native activation remains pending. |
| cgroup v2 | Upgrader reads the exact Agent system.slice cgroup and drains descendants; installer previously checked no unified hierarchy | Fresh installation/preflight require readable `cgroup.controllers`. Presence is not controller admission or enforcement. Native procedure checks cpu/memory/pids and effective limits. |
| Resource limits | Generated service has no CPUQuota, MemoryMax or TasksMax policy | No default resource ceiling claimed or silently added. Existing process/cgroup admission remains intact. A separately configured ceiling needs workload sizing/review. |
| Hardening | Existing NoNewPrivileges, PrivateTmp, ProtectSystem=full, empty capabilities, RestrictSUIDSGID, LockPersonality and UMask apply on both versions | Unit unchanged. `ProtectSystem=full` protects system directories; `ReadWritePaths` alone does not make all other paths read-only. Agent policy and Unix permissions remain necessary. Native namespace checks pending. |
| Users/groups | Official Noble images may preallocate UID 1000 | Test fixture no longer requests fixed UID 1000. Production system account already uses dynamically allocated system UID, nologin and prohibited-group checks. |
| Permissions/ACLs | Ubuntu user home/default permissions and existing POSIX ACLs vary by image/site | Real service-user private runtime execution and denial of config/app writes; narrow ACL traversal/read fixture and canonical alias check. No application chmod/chown/ACL changes in installer. |
| Source Access | Canonical realpath and independent host policy are version independent | Existing path, protected-path, host-delegation, revisions, leases, cancellation and receipt tests run on each OS. ACL access does not grant policy authority. |
| TLS/CA | Noble ships updated OpenSSL/CA packages; private Node uses its own TLS behavior | Generated synthetic CA, real HTTPS enrollment/HMAC heartbeat; actual wrong-CA and wrong-hostname checks fail. No TLS fallback. Private CA must be readable by service account. |
| Node/Corepack/pnpm | Host Node versions differ; no system Node is used | Exact Node 22.18.0 archive checked against HTTPS versioned SHA-256 index, private Corepack and pnpm 10.20.0; frozen three-package lock. No native npm modules or global installs. |
| glibc/binaries | Jammy glibc 2.35 versus Noble 2.39 | Execute verified Node, Restic 0.19.1, rclone 1.75.1 as real service user. Real Restic local backup/restore/exclusions fixture on each OS; no real remote storage. |
| Python | Jammy Python 3.10 versus Noble 3.12 | Python standard library is needed only by the synthetic server fixture. Production installer/runtime do not require Python or pip. No system Python packages installed through pip. |
| Packages | Noble has package/library transitions including t64 names | Depend on utility package names, not private library paths. Required utility diagnostics now include previously omitted xz/stat/find/sort/xargs/cut/readlink. Fixture also installs ACL/locales/OpenSSL/Python for tests only. |
| Upgrade/provenance | Existing upgrader admits Linux x64 existing standalone layouts, not a fresh OS install | No OS migration or upgrade relaxation. Clean committed source, distribution marker, ownership/hash checks, durable backups, fences, bounded health and rollback remain unchanged. Test models run on both userlands; native lifecycle pending. |
| Fresh-install guards | Previous refusal missed dangling symlinks, a leftover unit or an inaccessible state directory | Refuse app/config/state/unit paths including dangling symlinks before account/download changes; never infer absence of identity inside private state. Use protected app-only upgrade, not reinstall. |
| Failed fresh installation | Existing pre-activation trap removes staging; late enrollment failure can retain private app/config/state without starting a service | New failure-boundary models assert both behaviors and refusal of residual state as fresh. Accounts/partial private state are not automatically deleted. Review residuals privately; automated late fresh-install rollback is not claimed. |

Noble's systemd/glibc/Python and AppArmor namespace changes are documented in the
[Ubuntu release notes](https://discourse.ubuntu.com/t/ubuntu-24-04-lts-noble-numbat-release-notes/39890/1).
The namespace restriction is a native acceptance concern, not evidence that this
system service fails. Do not disable AppArmor or change sysctls to make a test pass.
Runtime requirements were reviewed against the
[Node 22.18.0 build contract](https://github.com/nodejs/node/blob/v22.18.0/BUILDING.md)
and the [systemd 255 execution contract](https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html).
These references inform the audit; executed tests determine the results.

## Reproduce the full container matrix

Use this repository alone; `.dockerignore` excludes original Git history,
dependencies, state, keys, credentials and generated artifacts. No host mounts,
privileged mode, host services or deployment credentials are used.

```sh
for version in 22.04 24.04; do
  docker build --platform linux/amd64 --progress=plain \
    --build-arg UBUNTU_VERSION="$version" -f tests/ubuntu/Dockerfile \
    -t "pluton-agent-validation:ubuntu-$version" . || exit
done
```

Both official base images are pinned by digest in the same Dockerfile. Ubuntu
package repositories are not a frozen snapshot; record installed versions from
the build log. Both matrix entries run the same suite; `fail-fast: false` keeps
one failure from hiding the other. Existing 22.04 scenarios/assertions are retained.
No dependency, source golden vector or runtime capability version changes.

The stages cover:

1. Clean Agent-only source, no global Node or pnpm; real downloads/checksums,
   frozen install and TypeScript build using private tools.
2. Unprivileged `install-agent.sh --check`, no token/network/install writes;
   actual system account, permissions, identity, config and generated unit.
3. Synthetic loopback TLS enrollment and authenticated capability heartbeat;
   wrong CA/hostname fail; no queued work leased in installation health check.
4. Existing installation and legacy provenance refusal with exact preserved
   config/identity evidence; locale-independent installed integrity validation.
5. All Agent tests as an unprivileged user: command signatures/expiry/version
   refusal, Source Access/delegation, exclusions, replay/receipts, synthetic
   database/hooks, failure reporting and real local Restic filesystem backup.
6. Original installer checksum/failure/reuse/rollback harness plus new OS,
   cgroup-v1, read-only argument and dangling-path negatives. Test-mode reuse
   scenarios are regression models, not permission for production reinstall.
7. Upgrade integrity/rollback/crash/durability and locale models with C, C.UTF-8
   and a privately generated en_US.UTF-8. No actual systemd lifecycle in models.
8. Pinned server-generated contract vectors and normalized original runtime
   source hashes, source boundary check, Bash syntax, fresh release packaging
   twice, identical manifests and archive SHA-256 verification.

The Python HTTPS fixture validates signed requests but is not the Pluton Server.
Unit/lifecycle transport fixtures cover signed backup commands, receipts and
failures separately; the Python installer fixture does not lease backup jobs.
No current deployed-server certification or real DB/SFTP recovery is implied.

## Read-only compatibility preflight

Run without sudo from reviewed source, with intended roots already present:

```sh
bash install-agent.sh --check --server https://pluton.example.internal \
  --allowed-root /srv/example-app
```

Add `--ca-file /absolute/approved-ca.pem` for a private CA. No token options are
accepted. It checks Ubuntu target/architecture, utility availability, systemd
presence, unified hierarchy, source layout/package-manager pin, canonical roots
and existing installation paths. It creates no directories, downloads nothing,
reads no enrollment token and performs no service or OS mutations. Existing
private state is refused without needing to inspect its identity.

It cannot prove service-user access before that user exists, validate PEM trust
against a remote endpoint, certify source authenticity or run a privileged
controller/namespace experiment. A PASS is local prerequisite evidence only.
Source archives remain valid fresh-install inputs; preflight does not pretend
to verify an immutable Git commit for an archive. Verify SHA/delivery provenance
separately. The app-only upgrader retains stronger clean-Git/provenance admission.

## Recommended server enrollment UI wording (separate change)

Until native acceptance: "Linux x86_64: Ubuntu Server 22.04 LTS previously
validated. Ubuntu Server 24.04 LTS validation candidate; native systemd acceptance
pending. Use an approved immutable standalone Agent commit and review its test
results before installation."

After full acceptance for the exact commit: "Ubuntu Server 22.04 / 24.04 LTS
x86_64, systemd and unified cgroup v2. Fresh installation only."

Keep authenticated HTTPS, one-time private token prompt, explicit allowed roots,
Server-Managed Source Access and host delegation instructions. Do not say
"all Linux", "any Ubuntu" or claim 24.04.5 ISO coverage from a container tag.
No separate Pluton Server repository/UI was modified here.

## Execution results

Local execution date: **2026-10-22**. Both complete isolated matrix runs passed,
including the added fresh-failure models. The Docker userlands identify as
**22.04.5** and **24.04.5**; these are
not booted Server ISO tests. Logs/artifacts remain ignored under `tmp/validation`
and inside disposable images, not committed as evidence or runtime state.

| Check | Ubuntu 22.04 x86_64 | Ubuntu 24.04 x86_64 |
| --- | --- | --- |
| Private pinned downloads, checksum checks, frozen install, typecheck/build | PASS | PASS |
| Fresh source installation, service account, config/identity ownership/private runtime | PASS | PASS |
| Public unprivileged read-only preflight | PASS | PASS |
| Generated unit parsed by real systemd-analyze | PASS, systemd 249 | PASS, systemd 255 |
| Narrow ACL/traversal, canonical alias, config-read/app-write denial | PASS | PASS |
| Synthetic CA enrollment, authenticated heartbeat/version/capability | PASS | PASS |
| Actual wrong CA / wrong hostname refusal | PASS | PASS |
| Agent tests: commands, Source Access, exclusions, synthetic DB/hooks, receipts/failures, real local Restic | 157 PASS, 0 FAIL, 0 SKIP | 157 PASS, 0 FAIL, 0 SKIP |
| Versioned golden contracts, source parity, docs/release negatives | 6 PASS, 0 FAIL, 0 SKIP | 6 PASS, 0 FAIL, 0 SKIP |
| Installer safety shell harness including OS/cgroup/dangling-path/preflight negatives | PASS | PASS |
| Early fresh failure staging cleanup / late enrollment failure residual guards | PASS | PASS |
| Upgrade/rollback/provenance/durability/locale tests | 62 PASS, 0 FAIL, 0 SKIP | 62 PASS, 0 FAIL, 0 SKIP |
| C, C.UTF-8, real en_US.UTF-8 integrity | PASS, no accepted-record rewrite | PASS, same canonical test digest |
| Standalone source/dependency boundary, Bash syntax | PASS | PASS |
| Fresh release packaging twice, identical manifests, all artifact checksums | PASS | PASS |
| Native-only synthetic server mode refuses container | Not a native execution | PASS refusal guard only; native mode still pending |
| Native activation/reboot/shutdown, cgroup limits, namespace enforcement, upgrade lifecycle | PENDING | PENDING |

Workflow actionlint, `git diff --check`, and a review/credential-pattern scan of
changed public source/docs also passed. No generated state, secrets, binaries or
private evidence are included in the local commits. Container release manifests
bind the fixture's synthetic source commit; these are packaging regression tests,
not published artifacts for the final delivery commit.

Runtime files, wire contracts, capability version, original normalized source
hashes and pinned dependency lock are unchanged. Golden vectors correspond to
server revision `9021b1274f3ea084a887446e321bc6984a688497`; no current deployed
Server was contacted. Optional parity against a separate current server checkout
was not rerun because that repository is outside this task. There is no Agent
version bump: installer/fixture/documentation changes preserve protocol 0.7.0.

The Windows host's global Node is 24.16.0; it was not used for validation. Initial
sandbox access to Docker/WSL was restricted; approved local Docker access enabled
the isolated runs. All builds/tests used private Node 22.18.0 and pnpm 10.20.0.
Hosted CI, native VM/exact Server ISO boot, current production server pairing,
real DB/SFTP recovery and production activation remain **NOT EXECUTED**.

## Changed files

- `.github/workflows/ci.yml`: two-release independent validation matrix.
- `installers/install-agent.sh`: read-only check, explicit Ubuntu target validation,
  unified hierarchy/missing-tool checks and stricter fresh-install path refusal.
- `installers/tests/install-agent.test.sh`: platform, preflight, path and fresh
  failure regression cases; existing assertions retained.
- `tests/ubuntu/Dockerfile`: pinned 24.04 stage, shared suite, ACL tools,
  dynamically allocated test UID and explicit standalone boundary validation.
- `tests/ubuntu/fresh-install.sh`: actual OS/tool reports, unprivileged preflight,
  unit parsing, ownership/account/ACL checks and TLS rejection cases.
- `tests/ubuntu/systemctl-fixture.sh`: accurate installed version and adapter label.
- `tests/ubuntu/mock-control-plane.py`: opt-in native disposable-VM idle fixture
  with synthetic identity/proof persisted across reboot; default no-poll behavior retained.
- `README.md`, `docs/OPERATIONS.md`, `docs/COMPATIBILITY.md`,
  `docs/AGENT_UPGRADE.md`, `docs/RELEASES.md`, `docs/EXTRACTION_AUDIT.md`,
  `docs/UBUNTU_VALIDATION.md`, `docs/NATIVE_SYSTEMD_ACCEPTANCE.md`: installation,
  troubleshooting, audit/results, support boundaries, server wording and native gate.
