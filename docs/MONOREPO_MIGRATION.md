# Migrating a Server-monorepo Agent to this distribution

Agents installed before this repository existed came from the Pluton Server
monorepo installer (`installers/install-agent.sh` in the Server repository). They
report Agent 0.7.0, run private Node 22.18.0 and cannot use this repository's
upgrader, which refuses provenance without
`distribution=pluton-agent-standalone-v1`. Re-enrolling would create a new device
and orphan every backup plan bound to the old one.

`upgrade-agent.sh --migrate-monorepo` moves such an installation in place. It is the
normal guarded upgrade transaction with one extra precondition and one extra
provenance line. The device, Agent ID, secret, roots, delegations, receipts and plans
stay as they are. No server change, token or re-enrollment is needed.

## Why this is safe to do in place (proven from source)

| Fact | Evidence |
| --- | --- |
| Same Agent code and state formats | Monorepo `agent/src` at Server commit `c187e2c` is byte-identical to the extraction base `9021b12` recorded in `contracts/extraction-source.json` (no `agent/src` changes between them). |
| Same unit and config files | `write_systemd_unit` and `write_config` in the monorepo installer at `c187e2c` and in this repository are identical, so the unit/config contract checks apply unchanged. |
| Same drain/hold protocol | `agent/src/upgradeGuard.ts` is identical; a running monorepo Agent already answers `--upgrade-info` with protocol v1. |
| Same integrity record | `verified_tree_digest` is the same algorithm (this repository only scopes `LC_ALL=C` inside it), and the monorepo `.verified-install` has the same `format=1` lines minus the marker. |
| Supported runtime | The upgrader already supports the Node 22.18.0 baseline and installs the reviewed 22.23.4 runtime in the same transaction. |
| HTTP LAN transport kept | `ALLOW_INSECURE_HTTP=true` with an `http://` server URL is honored by this Agent (`agent/src/config.ts`, `network.ts`; covered by the existing transport tests). |

A monorepo `--check` that reports "Installed artifacts differ from their recorded
integrity digest" when run from an old monorepo checkout is usually the locale
defect fixed in Server commit `1ec588b`: rerun it as
`sudo env LC_ALL=C bash installers/upgrade-agent.sh --check`. A PASS proves the
installed tree matches its record.

## What the migration checks and changes

Refused unless all of these hold (otherwise nothing is touched):

- The installed `.verified-install` is exactly the monorepo installer record:
  `format=1`, `node=v22.18.0|v22.23.4`, `restic`, `rclone`, `node_archive`,
  `source`, `tree`, in that order, and **no** `distribution=` line. A standalone
  installation is refused ("Already a standalone installation").
- Every existing upgrade precondition: root-protected paths and provenance, tree
  digest, pinned Node/Restic/Rclone, the exact installer unit and service contract,
  literal EnvironmentFile, private identity/state, local drain and hold protocol,
  clean committed checkout, disk headroom.

Then it runs the same transaction as a normal upgrade: build from this checkout,
fence and drain, back up the app, runtime, config, unit and old provenance, swap app
and runtime, write provenance, start, signed heartbeat, release. The new provenance
is the old record with refreshed `source`/`tree`/`node`/`node_archive` plus the
`distribution=pluton-agent-standalone-v1` line. The receipt records
`"migration": "monorepo"`.

Rollback restores the exact old app, runtime and the old provenance bytes, so the
result is again a valid monorepo installation that its old monorepo checkout can
upgrade. Without the marker, `--rollback` is accepted only for a receipt that records
this migration; ordinary receipts are refused.

## Operator procedure

Paths are synthetic. Run Git as the checkout owner and only the upgrader with sudo.

1. In Pluton, pause the Agent's plans. Wait for running backups to finish and make
   sure no Source Access request is pending.
2. Optional, from the existing monorepo checkout, prove the installed tree is intact:
   ```bash
   cd /srv/pluton && sudo env LC_ALL=C bash installers/upgrade-agent.sh --check
   ```
3. Clone this repository and check out the reviewed commit:
   ```bash
   git clone https://github.com/OWNER/pluton-agent.git /srv/pluton-agent
   cd /srv/pluton-agent
   git checkout --detach REVIEWED_40_HEX_SHA
   test -z "$(git status --porcelain --untracked-files=all)" && echo clean
   ```
4. Preflight, then migrate:
   ```bash
   sudo bash upgrade-agent.sh --migrate-monorepo --check
   sudo bash upgrade-agent.sh --migrate-monorepo
   systemctl is-active pluton-agent
   ```
   Record the `Upgrade ID` from the last line.
5. In Pluton: same machine and Agent ID, ONLINE, Agent 0.7.1, same capabilities and
   effective roots. Run **Backup Now** for one plan, check the snapshot, then resume
   the plans.

From now on use the normal standalone procedure from this checkout
(`sudo bash upgrade-agent.sh --check`, then `sudo bash upgrade-agent.sh`). Keep the
old monorepo checkout until you no longer need rollback.

### Rollback

Automatic: a failure after the service stopped restores the monorepo app, runtime and
provenance and prints `Rollback: SUCCESS`. Manual, while plans stay paused:

```bash
sudo bash upgrade-agent.sh --rollback <upgrade-id>
systemctl is-active pluton-agent
```

Rollback is refused once identity, receipts, roots, policy or configuration have
changed after the migration (same rule as every upgrade). Do not edit the marker,
delete locks/holds or reinstall to work around a refusal.

## Defect found and fixed: manual rollback after a completed upgrade

Applies to every standalone installation, not only migrations.

- **Proven (lab):** `upgrade-agent.sh --rollback <id>` for a transaction that had
  already completed (`phase: healthy`, its activity fence released) failed with
  `MANUAL_ROLLBACK` / `UPGRADE_CHECK_FAILED`. `rollback()` publishes a new activity
  fence and chowns it to the service account using `c.agentUid`, which only
  `preflight()` resolved; manual rollback never runs preflight, so the UID was
  undefined. The exclusive create had already happened, leaving an empty
  root-owned fence and the installation hold in place: the Agent stayed held and a
  retry was refused ("Unknown/live activity fence").
- Not affected: automatic rollback inside a failed upgrade (preflight already ran)
  and rollback of an interrupted transaction whose own fence still exists.
- Fix: the production context resolves the `pluton-agent` UID/GID for every mode;
  `rollback()` refuses before creating any hold or fence if the account is unknown;
  `acquireActivity()` validates the account before its exclusive create.
- Earlier labs only rolled back interrupted transactions, and the unit fixture
  always supplied the UID, so this path was never exercised. The new lab performs a
  CLI rollback of a completed, runtime-changing transaction; a unit test covers the
  refusal ordering.

## Validation

| Check | Result |
| --- | --- |
| Transaction suite, Windows (`node --test installers/tests/upgrade-agent*.test.cjs`) | 74 tests: 59 passed, 7 Linux-only skipped. The 8 runtime/symlink cases that need Windows symlink privilege fail with `EPERM` exactly as on unmodified `main` (50 passed there); one timing-sensitive provenance deadline case failed once under load and passed on two isolated reruns |
| New cases | Exact provenance policy (8 malformed records refused), marker-only provenance change, CLI allowlist, lineage receipt, explicit rollback to exact monorepo bytes, failed-start automatic rollback, interrupted migration rollback through its own receipt, ordinary receipt refused without the marker, manual rollback refusing before any hold/fence when the account is unknown |
| Bash entry point | Unsupported migration argument forms exit 2; `--help` documents the mode |
| Ubuntu 22.04 `validation` target (same as hosted CI) | PASS: Agent typecheck/tests, contracts, installer suites, upgrade transaction suite 79/79 with no skips (including the symlink/runtime cases Windows cannot run), packaging |
| Ubuntu 22.04 `runtime-upgrade` target | PASS: real 22.18.0 to 22.23.4 runtime upgrade, failed start, anchored rename-gap recovery |
| Disposable Ubuntu 22.04 lab (`scripts/validate-monorepo-migration.ps1`, monorepo `c187e2c`) | PASS: real monorepo install (no marker, Node v22.18.0, Agent 0.7.0); ordinary upgrade refused and migration preflight read-only; failed start restored the exact monorepo provenance/runtime/app; migration kept identity/config/unit/policy/receipts and added only the marker (Node v22.23.4, Agent 0.7.1, tree digest verified); normal `--check` passes afterwards; CLI rollback restored the exact monorepo record; repeat migration passed; one enrollment, no polls, signed heartbeats |

The lab installs a real monorepo Agent from a read-only snapshot of the Server
repository at the given commit (only `installers/`, `agent/` and the root workspace
files), with real private downloads, build, TLS enrollment and heartbeat against the
synthetic control plane. It then runs the reviewed upgrader: ordinary path refused,
migration preflight, failed start with automatic rollback, successful migration,
explicit rollback to the exact monorepo provenance, and a second migration. Only
systemd is adapted (container `systemctl` fixtures).

```powershell
pwsh -File scripts/validate-monorepo-migration.ps1 -MonorepoCheckout C:\path\to\pluton -MonorepoCommit <monorepo-40-hex-sha>
```

## Limits

- Booted systemd, cgroup enforcement and a real Pluton Server pairing were not
  exercised; the lab adapts `systemctl` and uses the synthetic control plane over
  HTTPS. HTTP LAN transport is covered by Agent unit tests, not by the lab.
- Only installations whose provenance is the exact monorepo record are supported.
  Custom units, drop-ins, other paths or hand-edited records still need review.
- Requires network access to GitHub, the npm registry and nodejs.org for the build,
  like every upgrade.
- The server's enrollment pin (`AGENT_INSTALL_*`) is unrelated; this procedure never
  reads it.
