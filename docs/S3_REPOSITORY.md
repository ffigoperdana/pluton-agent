# S3 repositories for Managed Agent plans (Agent 0.8.0)

Design: Pluton server repository, `docs/S3_AGENT_REPOSITORY_DESIGN.md` (approved
15 November 2026), stage 1, Agent part: sections 6.2, 6.3, 6.6, 6.7, 7 and the
wire contract in section 10. Branch: `claude/agent-s3-repository` from
`origin/main` `4c2c3f3`.

## Goal

A Managed Agent plan can use an S3-compatible repository (HCP) as its primary.
The Agent writes directly to S3 from its own host; nothing passes through the
Pluton server. Existing SFTP plans and payload versions 1 to 4 are unchanged.

## What changed

- **Sealed secrets** (`agent/src/sealedSecrets.ts`): the version 5 `sealed` field
  is opened with HKDF-SHA256 over the per-Agent secret (info
  `pluton-agent-command-secrets-v1`) and AES-256-GCM, with the command ID and lease
  token as additional data. The runtime passes `identity.secret`, `command.id` and
  `command.leaseToken`, the same values that verified the command HMAC. Opening
  happens during `payload-validation`, before any file is written. The sealed
  field carries the repository password, the SFTP password or both S3 keys, and
  every database password (`lifecycle.database` for lifecycle shape 1, or
  `lifecycle.databases` keyed by `databaseId`); the Agent restores each database
  password into a copy of its lifecycle entry and refuses a plain database
  password, a database without a sealed password or an unmatched sealed password.
  Sealing database passwords was a user decision of 15 November 2026 (design
  section 10.3).
- **Payload version 5** (`agent/src/backupFilesystem.ts`): `rclone.type` `sftp` or
  `s3`; S3 plain options `provider`, `endpoint` (HTTPS origin), `region`,
  `location_constraint`, `acl`, `force_path_style` (`true`),
  `use_accept_encoding_gzip` (`false`), `no_check_bucket`; SFTP plain options
  `host`, `port`, `user`. Plaintext credentials or a top-level repository
  password are refused. An S3 path must be a prefix inside a bucket.
- **Version 3/4 rules inside version 5**: anchored exclusions and the pre-backup
  scan only with exclusions (as version 4); source binding and receipt recovery
  with a version 2 lifecycle (as version 3).
- **S3 configuration**: `[pluton] type = s3` with `env_auth = false`, keys not
  obscured, directory 0700 and file 0600, removed in `finally`.
- **Trust**: optional root-owned `PLUTON_AGENT_STORAGE_CA_FILE`, passed to Restic
  and Rclone as `SSL_CERT_FILE` for S3 only (`agent/src/config.ts`,
  `agent/src/index.ts`, `installers/install-agent.sh --storage-ca-file`). The
  installer also refuses a path with control characters.
- **Checks and classification**: an Rclone listing of the prefix before Restic
  (Restic's Rclone bridge hides provider errors); an empty S3 listing is an empty
  target, a missing bucket never is; S3 authentication, access and transport text
  (including TLS, DNS and 5xx) maps to the existing closed codes.
- **Backup failure classification (user decision, 15 November 2026)**: a failing
  `restic backup` on S3 is classified as a storage failure only from storage
  lines (`rclone: ` lines and backend-context lines). Every Restic `error:` line
  is a source error, so an NFS or other source read failure is never reported as
  a storage failure. The markers were not verified against the Restic 0.19.1
  source; an unrecognised line falls back to `restic-backup-failed`.
- **Capabilities and version**: `repositoryBackends: ["sftp", "s3"]`,
  `backupPayloadVersion: 5`, Agent 0.8.0, contract `pluton-agent-0.8.0`
  (`contracts/v0.8.0.json`). A typo in the plan's command signature was corrected;
  the signed command in the contract is verified with `verifyCommand`.

## Security

The S3 key is the shared HCP user (risk accepted by the operator on 15 November
2026): a compromised Agent host can read and delete every plan's S3 data in that
namespace. The key is sealed on the wire, so HTTP Agent traffic on the LAN does not
expose it; it exists only in Agent memory and the temporary 0600 configuration
during one backup and is never logged or persisted (completion receipts carry no
secrets). Database passwords are sealed the same way in version 5, so no secret
of a version 5 command crosses the network in plain text. The sealing key differs
from the HMAC key, and a sealed field cannot be replayed into another command or
lease. The Agent never receives replica keys.

Residual risk: the per-Agent secret that keys the sealing is returned in the
enrollment response. Enrol an Agent that will use an S3 primary over HTTPS
(`AGENT_SERVER_URL` with `https://`); over plain HTTP a passive observer of
enrollment could open sealed payloads.

## Tests

| Check | Command | Result |
| --- | --- | --- |
| Sealing vector, every single-byte/character mutation, sealed database passwords | `node --test agent/dist/sealedSecrets.test.js` | PASS (Windows and Ubuntu) |
| Payload v5 parsing, allowlists and database password restore/refusals | `backupFilesystem.test.js`, `payload v5:` tests | PASS |
| Runtime binding to secret, command ID and lease token | `sealedCommandRuntime.test.js` | PASS (Ubuntu) |
| v5 keeps version 3/4 source rules | `backupFilesystem.test.js`, `backupLifecycle.test.js` | PASS (Ubuntu) |
| S3 config, CA, access check, empty target, classification (storage lines only) | `backupFilesystem.test.js`, `S3:` tests | PASS (Ubuntu) |
| Contract vectors, standalone parity, release identity | `pnpm test:contracts` | PASS (Windows and Ubuntu) |
| Installer `--storage-ca-file`, including control characters | `bash installers/tests/install-agent.test.sh` | PASS (Ubuntu) |
| Full Ubuntu 22.04 and 24.04 validation images | `docker build --target validation` and `--target runtime-upgrade` | PASS |

Docker post-dump lab (`scripts/validate-post-dump.ps1`, Ubuntu 22.04 and 24.04
tool images, real MySQL 8 dump, real Restic 0.19.1 and Rclone 1.75.1, HTTPS
`rclone serve s3` with a private CA generated per image build): 29 cases on each
image, the 24 existing SFTP cases unchanged and five S3 cases. The CA copied into
the lab image must be root-owned, because the Agent refuses a CA file that is not.

| Case | Expected outcome |
| --- | --- |
| `s3-healthy` | Success; snapshot and SQL artifact read back and hash-verified; restart replay does not execute again |
| `s3-untrusted-ca` (no `PLUTON_AGENT_STORAGE_CA_FILE`) | `repository-check` / `target-check-transport-failed`, no dump |
| `s3-wrong-key` | `repository-check` / `target-check-auth-failed`, no dump |
| `s3-non-empty` | `repository-target-check` / `repository-target-not-empty`, no init |
| `s3-tampered-seal` | `payload-validation` / `invalid-payload`, no backup state written |

Windows `pnpm test` keeps its four pre-existing platform failures from
`origin/main`; the Linux results above are authoritative.

## Operator steps

1. Deploy the server stage 1 release first. Its strict inventory schema must
   accept `repositoryBackends` and `backupPayloadVersion`, and its install gate
   must accept `AGENT_INSTALL_VERSION=0.8.0`. An older server refuses a 0.8.0
   Agent's enrollment and heartbeat.
2. After review and merge, set in the server `.env`:
   `AGENT_INSTALL_COMMIT` to the full 40-hex SHA of the reviewed 0.8.0 Agent merge
   commit and `AGENT_INSTALL_VERSION=0.8.0`.
3. Run the stage 0 probe on the Agent host. Only if TLS does not verify with the
   system trust store, install the CA bundle as root (the file must contain every
   CA the endpoint needs, because it replaces the system store for Restic and
   Rclone):
   `sudo install -o root -g root -m 0644 approved-storage-ca.pem /etc/pluton-agent/storage-ca.pem`.
   The file and its directories must be root-owned, not group- or world-writable,
   and the file must not be a symbolic link.
4. Install the Agent on the new host from the reviewed commit, enrolling over
   HTTPS:

   ```sh
   bash install-agent.sh --check --server https://pluton.example.internal \
     --allowed-root /srv/example-app --storage-ca-file /etc/pluton-agent/storage-ca.pem
   sudo bash install-agent.sh --server https://pluton.example.internal \
     --allowed-root /srv/example-app --storage-ca-file /etc/pluton-agent/storage-ca.pem
   ```

   Omit `--storage-ca-file` when the system trust store verifies the endpoint.
   For an Agent that is already installed, drain it, add
   `PLUTON_AGENT_STORAGE_CA_FILE="/etc/pluton-agent/storage-ca.pem"` to
   `/etc/pluton-agent.env` as root and run `sudo systemctl restart pluton-agent`.
5. Confirm in the UI that the device reports Agent 0.8.0 and that S3 storages are
   offered for its plans. Create the plan with a new, empty prefix inside the
   bucket.
6. Run one backup and check the journal privately:
   `journalctl -u pluton-agent --since '30 minutes ago' --no-pager | grep -E 'storage access verified|backup completed'`.
   Then verify the snapshot, a database artifact and a restored sample in the UI.
7. On a failure, record only `failureStage`, `failureCode` and the journal
   `reason=` value; never share the environment file, the S3 key or provider
   output.

## Rollback

Agent first, then server. Roll the Agent back with `sudo bash upgrade-agent.sh
--rollback <upgrade-id>` (see [upgrade and rollback](AGENT_UPGRADE.md)); a host that
was installed fresh with 0.8.0 has no earlier version and is stopped or
uninstalled instead. With an Agent older than 0.8.0 the server refuses to queue a
backup for an S3-primary plan; snapshots already in S3 stay readable by the
server version that introduced the S3 read path. A leftover
`PLUTON_AGENT_STORAGE_CA_FILE` line is ignored by older Agents. Roll the server
back only after every 0.8.0 Agent is rolled back, because an older server refuses
the 0.8.0 heartbeat.

## Limits and follow-ups

- `PLUTON_AGENT_STORAGE_CA_FILE` replaces the system trust store for S3
  connections; the bundle must contain every CA the endpoint needs.
- One shared HCP key covers the whole namespace: a compromised Agent host can
  delete other plans' S3 data (risk accepted by the operator).
- The storage-failure markers (`rclone: ` lines and backend-context lines) were
  not verified against the Restic 0.19.1 source; unrecognised lines fall back to
  `restic-backup-failed`.
- `upgrade-agent.sh` accepts the new key (it allows `PLUTON_` keys) but does not
  yet check its readability during upgrade preflight; the Agent refuses an
  unreadable or non-root-owned file at backup time.
- `scripts/verify-server-contract.mjs` still checks the pinned 0.7.0 server
  revision; the server suite checks the 0.8.0 sealing vector on its side.
- No S3-to-SFTP replication, failover, primary switching, automatic prune or
  unlock (stages 2 to 4).
- The lab endpoint is `https://127.0.0.1:<port>`; its certificate also names
  `s3.example.internal`. Real HCP behaviour is confirmed by the stage 0 probe and
  the first operator backup, not by this lab.

## Changed files

`agent/src/sealedSecrets.ts` (new), `agent/src/sealedSecrets.test.ts` (new),
`agent/src/sealedCommandRuntime.test.ts` (new), `agent/src/backupFilesystem.ts`,
`agent/src/backupFilesystem.test.ts`, `agent/src/backupLifecycle.test.ts`,
`agent/src/runtime.ts`, `agent/src/types.ts`, `agent/src/config.ts`,
`agent/src/config.test.ts`, `agent/src/index.ts`, `agent/src/inventory.ts`,
`agent/src/inventory.test.ts`, `agent/package.json`, `package.json`,
`agent/examples/pluton-agent.env.example`, `contracts/standalone-source-v1.json`,
`contracts/v0.8.0.json` (new), `scripts/tests/contracts.test.mjs`,
`scripts/tests/runtime-pins.test.mjs`, `scripts/tests/release.test.mjs`,
`scripts/package-release.mjs`, `scripts/verify-release.mjs`,
`installers/install-agent.sh`, `installers/tests/install-agent.test.sh`,
`tests/post-dump/Dockerfile`, `tests/post-dump/native.lab.ts`, `README.md`,
`docs/OPERATIONS.md`, `docs/COMPATIBILITY.md`, `docs/S3_REPOSITORY.md` (new).
