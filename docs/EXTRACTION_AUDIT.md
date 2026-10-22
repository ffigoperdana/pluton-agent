# Standalone Linux Agent extraction audit

Subsequent Ubuntu 24.04 validation is recorded in the versioned
[Ubuntu compatibility audit](UBUNTU_VALIDATION.md), with a separate
[native VM gate](NATIVE_SYSTEMD_ACCEPTANCE.md). Historical extraction evidence
below remains scoped to its original run; it is not proof of native 24.04 support.

Independent runtime development after reviewed standalone main `095088b` is
recorded in [the HTTPS/enrollment audit](NETWORK_ENROLLMENT.md) and explicit
`contracts/standalone-source-v1.json`. The original extraction manifest and golden
protocol vectors are retained. Byte-identity statements below describe the
initial extraction, not the subsequent independently versioned transport changes.

## Scope and authority

Source: the merged Pluton main commit recorded in `contracts/extraction-source.json`.
Destination: independent `pluton-agent` Git repository, not a branch/worktree of
the server repository. The user's existing initial Git commit/remote are preserved.
The standalone branch is `codex/standalone-linux-agent`; publication is manual.

All Agent TypeScript source is byte-identical after LF normalization to the source
manifest: enrollment/HMAC/TLS, Source Access, path guards, backup versions 1–4,
exclusions v1, DB/hooks, cancellation, leases and command receipts are preserved.
No new enrollment/backup protocol, MySQL Internal operator or server resource guard
was implemented. No existing Agent, production source/storage or service was accessed.

## Complete external dependency and coupling inventory

| Monorepo dependency                                                | Standalone resolution                                                                                                                                                                                      |
| ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Root package.json with Server/frontend/turbo/hooks/release tooling | Replaced by private Agent-only orchestration package, pnpm 10.20.0 and one `agent` workspace; no prepare hook or global Git configuration                                                                  |
| Root lockfile and workspace including sibling server paths         | Minimal lock preserving TypeScript 5.9.3, @types/node 22.18.13, undici-types 6.21.0 and their original SHA-512 integrity values; frozen install                                                            |
| Agent tsconfig backend typeRoots fallback                          | Removed; only local Agent node_modules types remain; standalone typecheck verifies this                                                                                                                    |
| Agent runtime imports                                              | All local modules/Node built-ins; no third-party runtime package and no server/frontend import                                                                                                             |
| App package version 0.1.0 versus runtime 0.7.0                     | Package version aligned to unchanged advertised 0.7.0; not a wire capability change                                                                                                                        |
| Installer build root and fingerprint file list                     | Retained minimal directory layout and matching root lock/workspace files; original canonical C serialization retained                                                                                      |
| Installer support                                                  | Copied only Agent installer/upgrader, two support CJS modules and Agent tests; no server/desktop/platform installer                                                                                        |
| Private binaries                                                   | Existing exact Node version + HTTPS checksum index; embedded Restic/Rclone version/hash pins; no system Node/pnpm/Docker changes                                                                           |
| Fresh build assumes global Node in pnpm tsc launcher               | Actual clean Ubuntu reproduction failed `exec: node: not found`; scoped verified private runtime PATH added inside the build subprocess                                                                    |
| Upgrade source identity                                            | Existing clean committed-source `git archive`, pin validation, distribution boundary, durable backups/fsync, app activation, bounded provenance/health and rollback preserved; new repo's own Git SHA used |
| Installed tree provenance                                          | Existing format=1/hash algorithm preserved; additive standalone distribution marker is retained by original metadata-preserving upgrade/rollback; no failed-record rewrite                                 |
| Original installer existing-install behavior                       | Standalone production installer now refuses existing app/config/identity before mutation; monorepo migration is not implicit                                                                               |
| Unit/synthetic tests                                               | Copied all Agent source tests and installer safety tests; no assertions disabled                                                                                                                           |
| Old test-fixture Dockerfiles                                       | Removed from the extraction because some inherit old local images or import backend smoke scripts; replaced with self-contained pinned Ubuntu 22.04 fixture and original synthetic tool programs           |
| Real DB/phase 6 server integration                                 | Not copied as an Agent runtime dependency; remains server-owned and separately tested there                                                                                                                |
| Original GitHub workflows                                          | Replaced by Agent-only read-only CI: minimal build, contracts, checksum/release validation and isolated Linux installation/safety; no publication job                                                      |
| Server protocol definitions/cross-package tests                    | Frozen server-generated golden vectors and source hashes; retained server tests/source until separately reviewed migration                                                                                 |
| Server enrollment UI installer URL                                 | Not silently changed; operators use standalone checkout/token prompt; server template update remains a separate migration change                                                                           |
| Documentation                                                      | New README, operations, compatibility, release guide and migration audit; adapted detailed Agent upgrade/diagnostics authority; retained license/attribution                                               |

The default runtime environment, root ownership and permissions, private paths,
TLS, host approval/policy revisions, CLI command allowlist, DB privileges and
server-side replication/recovery responsibilities remain unchanged. Build-only
private PATH does not alter the system or service environment. No copied runtime
state, private config, identity, certificate, enrollment token or OCI archive is
tracked in this repository. Synthetic test credentials are explicitly disposable.

## Separate monorepo migration plan (NOT executed)

The new Agent repository is the proposed future authority, subject to review and
real hosted CI. Keeping the old source during validation is intentional; two
diverging live authorities are not the final design.

1. Review/publish the standalone source and immutable artifacts; run hosted Linux
   CI for the exact new commit. Record the server contract revision and retain
   currently installed app/identity/policy/receipts and rollback evidence privately.
2. Add server CI consumption of the versioned JSON conformance vectors by immutable
   digest. Keep existing HMAC/schema/exclusion and end-to-end tests until equivalent
   coverage is demonstrated; never replace them only with a mock.
3. Refactor server test imports from `agent/src`/`agent/dist`: control-plane integration,
   Source Access verification, repository-target validation and exclusions parity.
   Use a pinned Agent release test fixture or explicit contract-data adapter; do
   not require a mutable sibling checkout or network at production runtime.
4. Refactor `scripts/validate-phase6.ps1`, product-hardening and Restic-parent smoke
   harnesses that mount Agent output. They remain server-owned integration gates,
   using the exact published Agent test artifact instead of deleted source paths.
5. Update enrollment/install command generation, Agent docs links, monorepo workspace,
   packaging and Agent CI references in a separately reviewable server feature
   branch. Validate server/Agent compatibility before changing production behavior.
6. Design one separately authorized state-preserving **monorepo-to-standalone**
   migration: verify exact old provenance/toolchain/unit/state, drain all commands,
   preserve identity/TLS/config/roots/delegations/receipts/leases, record repository
   lineage, install reviewed app with transactional health/rollback. Do not simply
   add the distribution marker, re-enroll or copy a different identity.
7. Only after that acceptance, remove old `agent/`, Agent installer/support/tests
   and the Agent root-workspace build dependencies from the server. Keep server
   types, authentication, Source Access API/store/history, command generation,
   admission, replication, recovery and resource/root operator logic server-only.
   Keep the old app-only updater available for un-migrated installations until an
   explicitly approved end-of-support policy; no automatic source deletion now.

No original repository source was edited. The isolated fresh-build PATH defect
is documented for a future separately reviewed monorepo backport if required.
Existing production Agents remain entirely out of scope.

## Validation evidence

Logs, build output, dependency stores and generated release files remain ignored
under `tmp/`, `agent/dist`, `node_modules` and `release/`. The following are actual
local results, not hosted CI or production acceptance:

| Check                                                                              | Actual result                                                                                                                                                       |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Frozen minimal pnpm install                                                        | PASS, 3 packages; no monorepo dependency/importer                                                                                                                   |
| Standalone typecheck/build                                                         | PASS locally and on Ubuntu with the private Node toolchain                                                                                                          |
| Actual Ubuntu 22.04 fresh source installation                                      | PASS without original repository, original Git history, global Node or pnpm; real pinned downloads/hash checks/build, protected installed paths/account/config/unit |
| TLS enrollment + signed authenticated heartbeat                                    | PASS against synthetic loopback HTTPS API with generated CA/token/identity; version 0.7.0, exclusions capability 1, zero polls                                      |
| Linux Agent unit/integration fixtures                                              | 157 PASS, 0 FAIL, 0 SKIP; synthetic DB/hooks plus real pinned Restic exclusion test                                                                                 |
| Original first-install/reuse/failure installer harness                             | PASS; no existing host installation accessed                                                                                                                        |
| Linux upgrade, rollback, crash/durability and provenance/locale harness            | 62 PASS, 0 FAIL, 0 SKIP; C, C.UTF-8, real privately generated en_US.UTF-8 and precedence preserved                                                                  |
| Final contracts, docs and release negative tests                                   | 6 PASS, 0 FAIL, 0 SKIP; actual server-generated HMAC/exclusion vectors, unsupported backup version/shell fields, archive corruption/traversal, documentation links  |
| Independent optional server conformance                                            | PASS against the exact reviewed server revision and contract source hashes; read-only, not a required Agent dependency                                              |
| Production-branch legacy refusal on disposable installed Agent                     | PASS: existing install refused; missing marker rejects upgrade and destructive uninstall; config, unit, identity and failed legacy metadata unchanged               |
| Release packaging                                                                  | PASS on Linux: fresh pinned compilation, two source/app archives, full source commit, checksum verification and identical hashes across repeated packaging          |
| Bash syntax                                                                        | PASS for root wrappers, installer/upgrader and Ubuntu fixtures                                                                                                      |
| Privacy/source boundary                                                            | Reviewed intended public text files only; no real secrets/private infrastructure or generated state copied; no server/frontend source needed                        |
| GitHub Actions                                                                     | PREPARED, NOT RUN; user publishes manually; read-only validation workflow only                                                                                      |
| Real systemd/cgroup startup, production pairing, real DB/SFTP/application recovery | NOT TESTED                                                                                                                                                          |

The initial clean Ubuntu run proved the missing-private-PATH build failure; the
scoped correction then passed real source installation. A later upstream HTTP
502 interrupted a pinned binary download and safely failed; one unchanged retry
passed without relaxing TLS, version pins or checksums. An early BuildKit fixture
guard expected `/.dockerenv`, which BuildKit does not supply; the test now uses
its explicit image-only sentinel. The first synthetic v4 contract fixture used
an invalid short repository password; it was replaced with a legitimate synthetic
value, without changing the real minimum-length or admission checks.

Legacy uninstall is additionally guarded by root-owned, protected standalone
provenance. This is a distribution ownership boundary, not permission to remove
an unknown resource. The original repository and its deployment behavior remain
unchanged. The original production Agent is never mounted or contacted.

The Ubuntu test context contains only this standalone repository, no original
server/backend/frontend tree and no original Git history or host filesystem mount.
It starts without global Node/pnpm, performs real private tool downloads/hash
checks, frozen compilation, actual installation paths/account/ownership and TLS
enrollment with authenticated heartbeat against a synthetic local server. Systemd
calls use a deliberately labelled container adapter, not an actual booted service
manager. No real SFTP/database/application backup or production pairing is claimed.

## Release and operational limits

Source and app archive packaging is checksum-verifiable and rebuilds fresh with
the pinned compiler; source archives support fresh installation, while secure
app-only upgrades still require a clean Git checkout. App archives are not an
activation bypass. No automatic latest, publication, release credentials or
organization migration is implemented. Private registry/artifact distribution,
signing and real hosted CI remain separately approved work.

Read-only preflight, interrupted upgrades, original-state preservation, health
failures and rollback are covered by isolated tests. A real systemd/cgroup existing
Agent update, compatible production server enrollment, real data backup/recovery
and monorepo migration are **NOT TESTED**. This source candidate is for review/CI,
not automatic production acceptance.
