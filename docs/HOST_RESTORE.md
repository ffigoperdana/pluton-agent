# Restore to an Agent host (Agent 0.9.0)

Agent 0.9.0 can restore a snapshot of one of its own Managed Agent plans
**directly on its host**: the Agent reads the plan's SFTP or S3 repository itself
and runs `restic restore` into a new folder. Restored bytes never pass through
the Pluton server or a browser, so a 350 GB filestore or a multi-GB PostgreSQL
dump can be recovered from a small Pluton VM. The full design, including the
server side, is `docs/AGENT_HOST_RESTORE.md` in the server repository.

It never restores in place: there is no overwrite, merge or delete, and a
restore never lands inside a source root.

## 1. Host administrator: approve a restore root (once)

Choose an empty directory on a filesystem with room for the largest restore,
outside every backup source, the Agent state (`/var/lib/pluton-agent`) and
system trees (`/etc`, `/usr`, `/tmp`, `/var/tmp`, `/run`, `/boot`, `/root`, …),
below root-owned directories that no other account can write. `/srv/pluton-restore`
or `/var/backups/pluton-restore` are typical. Do not choose a directory that an
SFTP server on this host exports as a Pluton repository.

```sh
sudo install -d -o pluton-agent -g pluton-agent -m 0700 /srv/pluton-restore
sudo /opt/pluton-agent/runtime/bin/node /opt/pluton-agent/app/dist/index.js \
  restore-roots approve --config-file /etc/pluton-agent.env \
  --agent-id "$(sudo sed -n 's/.*"agentId":"\([^"]*\)".*/\1/p' /var/lib/pluton-agent/identity.json)" \
  --root /srv/pluton-restore
```

The command requires root, the enrolled Agent ID and a root that is a real,
canonical directory owned by `pluton-agent` with mode `0700`. It writes
`/etc/pluton-agent/restore-roots.json` (root-owned, `0644`) atomically and never
creates, chowns or chmods the root itself. `restore-roots list` shows each
root's status; `restore-roots revoke --root <path>` removes it. Up to 8 roots.
No service restart or unit change is needed: the stock unit
(`ProtectSystem=full`, no `ProtectHome`) already lets the service write a
directory it owns under `/srv`, `/var` or `/home`. Do **not** add a systemd
drop-in (`ReadWritePaths=`): the upgrader refuses a unit with drop-ins.
`PLUTON_AGENT_RESTORE_POLICY_FILE` in the root-owned `/etc/pluton-agent.env` may
move the policy file; a server command never can.

The Agent re-reads the policy at every heartbeat and at execution, reports each
root as `writable`, `unavailable` or `rejected` with a closed code
(`restore-root-owner`, `-mode`, `-overlap`, `-denied`, `-ancestor-unsafe`,
`-not-canonical`, `-missing`, `-not-writable`, …) and free bytes and inodes.
Pluton offers only `writable` roots.

## 2. What a restore does

For `RESTORE_FILESYSTEM` (payload version 1, secrets sealed exactly like backup
payload version 5) the Agent:

1. re-checks the policy and the root, refuses an existing `<name>` or
   `<name>.partial`;
2. checks the repository (`restic cat config`; S3 access through Rclone);
3. requires the exact full snapshot ID with the tags `pluton-plan-<planId>` and
   `pluton-backup-<backupId>`;
4. lists the selection (`restic ls --json --recursive`), refuses a missing path,
   and requires free space of the selected bytes plus the larger of 1 GiB and 5 %,
   free inodes for every entry plus 1,000, and 512 MiB in the state directory;
5. creates `<root>/<name>.partial` (mode `0700`, exclusive);
6. runs `restic restore <id> --target <partial> --overwrite never --verify --json`
   with `--include` or `--exclude` exact paths (never both);
7. for a database dump, checks the restored size and SHA-256 against the backup
   receipt;
8. renames `<name>.partial` to `<name>` only after all of that succeeded.

A folder without `.partial` is therefore complete and verified. A failure or a
cancellation after step 5 leaves `<name>.partial` for review; the Agent removes
only an empty `.partial` it created when Restic never started. A restore that is
retried after an Agent crash refuses `restore-target-exists`: review or remove the
partial folder and start a new restore with a new name.

Progress, the 10-minute lease renewal, cancellation (at most about 10 seconds),
the tolerance of short control-plane outages while Restic runs and the activity
fence used by upgrades are the same as for backups. Restic has a 72-hour limit.
`--verify` re-reads every restored file locally; it adds no repository traffic.

## 3. After the restore: ownership and moving data into place

The Agent runs without capabilities, so Restic cannot restore owners: every
restored file belongs to `pluton-agent:pluton-agent`, with original modes and
times, below the `0700` root. Original owners are visible in Pluton's snapshot
browser. Pluton never moves, chowns or deletes restored data. Typical steps:

```sh
sudo ls -la /srv/pluton-restore/<name>/srv/example-app/
# Filestore: stop the application, then copy with the right owner.
sudo rsync -aH --chown=odoo:odoo \
  /srv/pluton-restore/<name>/srv/example-app/filestore/ /srv/example-app/filestore/
# PostgreSQL dump: load into a NEW database first and check it.
sudo -u postgres createdb odoo_restore
sudo cat /srv/pluton-restore/<name>/pluton/database/odoo.sql | sudo -u postgres psql --dbname=odoo_restore
# When done:
sudo rm -rf --one-file-system /srv/pluton-restore/<name>
```

## 4. Failure codes

Stages: `payload-validation`, `restore-policy`, `target-creation`,
`tool-validation`, `sftp-password-obscure`, `temporary-storage-config`,
`repository-check`, `snapshot-validation`, `space-check`, `restic-restore`,
`artifact-verification`, `finalize`, `cleanup`, `command-status-check`. Codes:
`invalid-payload`, `restore-policy-invalid`, `restore-root-not-approved`,
`restore-root-unsafe`, `restore-root-overlap`, `restore-target-exists`,
`restore-target-failed`, `tool-unavailable`, `sftp-password-obscure-failed`,
`temporary-config-failed`, `repository-check-failed`,
`target-check-{access,auth,transport}-failed`, `restore-snapshot-mismatch`,
`restore-selection-missing`, `restore-insufficient-space`,
`restic-restore-failed`, `restore-verification-failed`,
`restore-finalize-failed`, `cancelled`, `unexpected` and the command-status codes.
Restic, Rclone and provider output never leave the host.

## 5. Not covered by automated tests

The Linux execution tests use fake Restic and Rclone programs and a fixture that
presents its ancestors as administrator-owned. A real Restic 0.19.1 restore from
a real SFTP or S3 repository on a booted systemd host, ACL/xattr-heavy data and a
350 GB run are **not tested**; run them on a disposable host before production use.
