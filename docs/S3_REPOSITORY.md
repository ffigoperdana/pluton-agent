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
  obscured, directory 0700 and file 0600, removed in `finally`. A configuration
  left behind by SIGKILL, OOM or power loss is swept when the service starts,
  before it polls for a command (`sweepStaleStorageConfigs`, `agent/src/runtime.ts`);
  the sweep is skipped while another live process holds the activity fence.
- **Trust**: optional root-owned `PLUTON_AGENT_STORAGE_CA_FILE`, passed to Restic
  and Rclone as `SSL_CERT_FILE` for S3 only (`agent/src/config.ts`,
  `agent/src/index.ts`, `installers/install-agent.sh --storage-ca-file`). The
  installer also refuses a path with control characters. Restic and Rclone are Go
  programs, which on Ubuntu still load `/etc/ssl/certs` when `SSL_CERT_FILE` is
  set, so the file adds the operator CA; it does not narrow trust (checked in the
  validation image: a certificate signed by a CA present only in `/etc/ssl/certs`
  still verifies with `SSL_CERT_FILE` naming another CA, and fails once
  `SSL_CERT_DIR` points elsewhere).
- **Checks and classification**: an Rclone listing of the prefix before Restic
  (Restic's Rclone bridge hides provider errors); an empty S3 listing is an empty
  target, a missing bucket never is; S3 authentication, access and transport text
  (including TLS, DNS and 5xx) maps to the existing closed codes.
- **Backup failure classification (user decision, 15 November 2026)**: a source
  (for example NFS) read failure must not be reported as a storage failure, and
  real storage failures are still detected when Restic itself gives up. The rules
  follow the output Restic 0.19.1 actually prints with `--json` through its Rclone
  backend (captured against Rclone 1.75.1 `serve s3`, see below) and its exit
  codes (`cmd/restic/main.go` maps every error except unreadable source files
  (3), no repository (10), an existing lock (11), a wrong password (12) and
  cancellation (130) to 1; 2 is a Go crash). A backend failure that reaches
  Restic's exit therefore gives 1, but a storage outage first seen as a lost lock
  may end as a cancellation (130) or with a final message without backend text;
  that is not verified and only adds runs reported as `restic-backup-failed`. A
  storage code needs Restic exit status 1 and a decisive final error: the JSON
  `exit_error` (or text-mode `Fatal: ` line) names the backend (`unexpected HTTP
  response (`, `error talking HTTP to rclone`), or Restic printed a give-up line
  whose own error is an HTTP answer other than 404 or 416 (`Save(<…>) failed:
  unexpected HTTP response (500)…`, also `Load`, `Stat`, `Remove`, `List`; never
  `rclone stdio connection already closed`). Then the category comes from the
  last 64 KB of stderr: the storage candidates are `rclone: ` lines, anchored
  backend call lines
  (`Save(<`, `Load(<`, `Stat(<`, `Remove(<`, `List(`), the JSON `exit_error`
  message and text-mode `Fatal: ` lines; every JSON `message_type` `error` line
  is a source line. Exit 3, any other exit status, a signal, a crash and the
  Agent's own deadline (for example a source read hung on an NFS hard mount) never
  give a storage code, whatever recovered retries are in the tail. A fatal storage
  failure wins over unreadable source files; the per-file source diagnostics are
  then not sent, because the server accepts them only with a source failure code.
  Anything else falls back to `restic-backup-failed`.
- **Capabilities and version**: `repositoryBackends: ["sftp", "s3"]`,
  `backupPayloadVersion: 5`, Agent 0.8.0, contract `pluton-agent-0.8.0`
  (`contracts/v0.8.0.json`). A typo in the plan's command signature was corrected;
  the signed command in the contract is verified with `verifyCommand`.

## Security

The S3 key is the shared HCP user (risk accepted by the operator on 15 November
2026): a compromised Agent host can read and delete every plan's S3 data in that
namespace. The key is sealed on the wire, so HTTP Agent traffic on the LAN does not
expose it; it exists only in Agent memory and the temporary 0600 configuration
during one backup and is never logged (completion receipts carry no secrets). The
configuration is removed after each backup and swept at start-up after a crash
(SIGKILL, OOM, power loss); until the service restarts, a crashed backup's
configuration stays on disk, readable only by the Agent account and root.
Database passwords are sealed the same way in version 5, so no secret
of a version 5 command crosses the network in plain text. The sealing key differs
from the HMAC key, and a sealed field cannot be replayed into another command or
lease. The Agent never receives replica keys.

Residual risk: the per-Agent secret that keys the sealing is returned in the
enrollment response. Enrol an Agent that will use an S3 primary over HTTPS: the
Agent takes `--server https://...` (stored as `PLUTON_SERVER_URL`), and the
install command generated by the Pluton server takes that URL from the server's
`.env` setting `AGENT_SERVER_URL`, or from `APP_URL` when `AGENT_SERVER_URL` is
unset, so make whichever one is used an `https://` origin. Over HTTPS the
enrollment response is protected. Over plain HTTP a passive observer of the
enrollment could derive the sealing key and open that Agent's sealed payloads;
this is an accepted residual risk only if the operator chooses HTTP. An Agent
already enrolled over HTTP keeps a per-Agent secret that may have been observed:
re-enrol it over HTTPS before giving it an S3 primary, or record that risk.

## Tests

| Check | Command | Result |
| --- | --- | --- |
| Sealing vector, every single-byte/character mutation, sealed database passwords | `node --test agent/dist/sealedSecrets.test.js` | PASS (Windows and Ubuntu) |
| Payload v5 parsing, allowlists and database password restore/refusals | `backupFilesystem.test.js`, `payload v5:` tests | PASS |
| Runtime binding to secret, command ID and lease token | `sealedCommandRuntime.test.js` | PASS (Ubuntu) |
| v5 keeps version 3/4 source rules | `backupFilesystem.test.js`, `backupLifecycle.test.js` | PASS (Ubuntu) |
| S3 config, CA, access check, empty target, classification (storage lines only) | `backupFilesystem.test.js`, `S3:` tests | PASS (Ubuntu) |
| Classification from captured Restic 0.19.1 JSON output (exit 3, JSON source errors, `exit_error`, tail beyond 64 KB; no storage code for a hang ended by a signal, SIGKILL, exit 130, 2, 11 or a local exit 1 after recovered retries, nor for a give-up line that is a 404, a 416 or a closed Rclone stdio connection) | `backupFilesystem.test.js`, `S3: captured Restic 0.19.1` tests | PASS (Ubuntu) |
| Stale temporary storage configs swept at service start-up, not while another live process holds the activity fence | `backupFilesystem.test.js` (`sweeps stale`), `operationalHardening.test.js` (`service start-up sweeps`) | PASS (Ubuntu) |
| Contract vectors, standalone parity, release identity | `pnpm test:contracts` | PASS (Windows and Ubuntu) |
| Installer `--storage-ca-file`, including control characters | `bash installers/tests/install-agent.test.sh` | PASS (Ubuntu) |
| Full Ubuntu 22.04 and 24.04 validation images | `docker build --target validation` and `--target runtime-upgrade` | PASS |

Docker post-dump lab (`scripts/validate-post-dump.ps1`, Ubuntu 22.04 and 24.04
tool images, real MySQL 8 dump, real Restic 0.19.1 and Rclone 1.75.1, HTTPS
`rclone serve s3` with a private CA generated per image build): 32 cases on each
image, the 24 existing SFTP cases unchanged, one SFTP payload version 5 case and
seven S3 cases. The CA copied into the lab image must be root-owned, because the
Agent refuses a CA file that is not.

| Case | Expected outcome |
| --- | --- |
| `sftp-v5-sealed` | SFTP payload version 5 with `excludes: ["node_modules"]`, `sourceDiagnosticsVersion: 1` and a version 2 lifecycle; repository, SFTP and database passwords sealed, none in plain text; success, SQL artifact hash-verified, the excluded directory absent from the snapshot, restart replay does not execute again |
| `s3-healthy` | Success; snapshot and SQL artifact read back and hash-verified; restart replay does not execute again |
| `s3-untrusted-ca` (no `PLUTON_AGENT_STORAGE_CA_FILE`) | `repository-check` / `target-check-transport-failed`, no dump |
| `s3-wrong-key` | `repository-check` / `target-check-auth-failed`, no dump |
| `s3-non-empty` | `repository-target-check` / `repository-target-not-empty`, no init |
| `s3-tampered-seal` | `payload-validation` / `invalid-payload`, no backup state written |
| `s3-fails-at-backup-start` | The endpoint (an HTTPS front of the fixture) stops at "restic backup started", after the access check, init and dump: `restic-backup` / `target-check-transport-failed` from the JSON `exit_error` alone (about one minute, Restic's Rclone start-up timeout) |
| `s3-fails-during-upload` | The endpoint stops at the first pack upload of `restic backup`: `restic-backup` / `target-check-transport-failed` from the `rclone:` lines after Restic gives up (21 minutes on Ubuntu 22.04 and 35 minutes on 24.04 in the last run, all Restic retries) |

### Captured Restic 0.19.1 output

Captured in the Ubuntu validation image with `restic backup --json` through the
Rclone backend against Rclone 1.75.1 `serve s3` over HTTPS with a private CA
(synthetic data; paths and object names shortened here). Everything below is on
stderr; the summary is on stdout.

- Unreadable source file and directory (exit 3, snapshot saved):
  `{"message_type":"error","error":{"message":"open /src/app/unreadable.txt: permission denied"},"during":"archival","item":"/src/app/unreadable.txt"}`
  (also `"during":"scan"`), then
  `{"message_type":"exit_error","code":3,"message":"Warning: at least one source file could not be read"}`.
  An EIO read gives `"message":"failed to save /proc/self/mem: read /proc/self/mem: input/output error"`, same shape and exit 3.
  Text mode prints `error: open ...: permission denied` and
  `Warning: at least one source file could not be read`.
- Wrong key (exit 1 after about 15 minutes): only
  `Stat(<config/>) returned error, retrying after 904.774335ms: unexpected HTTP response (500): 500 Internal Server Error`
  lines, `Stat(<config/>) failed: ...`, then
  `{"message_type":"exit_error","code":1,"message":"Fatal: unable to open config file: unexpected HTTP response (500): 500 Internal Server Error\nrclone:pluton:bucket-01/repo"}`.
  The Rclone bridge prints no provider text for this, which is why the Agent
  checks access with Rclone first. Text mode prints the same message as a
  `Fatal: ` line.
- Endpoint answering 403, 503 or refusing connections after a few pack uploads
  (403 and refused: exit 1 after about 21 minutes; 503: the data save gave up
  after about 14 minutes, but Restic kept retrying a new lock and was stopped
  after 35 minutes): `rclone: 2026/11/15 17:03:06 ERROR : data/00/<id>: Post request put error: operation error S3: PutObject, https response error StatusCode: 403, RequestID: 1, HostID: , api error AccessDenied: Access Denied`
  (503: `... exceeded maximum number of attempts, 1, https response error StatusCode: 503, ... api error ServiceUnavailable: Service Unavailable`;
  stopped: `... request send failed, Put "https://<endpoint>/<bucket>/<prefix>/data/<id>?x-id=PutObject": dial tcp <endpoint>: connect: connection refused`),
  each followed by `Save(<data/<id>>) returned error, retrying after ...: unexpected HTTP response (500): 500 Internal Server Error`;
  then `Save(<data/<id>>) failed: ...`, `unable to refresh lock: ...`, lock
  `Remove(<lock/<id>>)` retries with `rclone: ... Delete request remove error: ...`
  lines, `error while unlocking: context canceled` and finally
  `{"message_type":"exit_error","code":1,"message":"Fatal: unable to save snapshot: unexpected HTTP response (500): 500 Internal Server Error"}`.
- Endpoint already gone when `restic backup` starts (exit 1 after about one
  minute, no other line):
  `{"message_type":"exit_error","code":1,"message":"Fatal: unable to open repository at rclone:pluton:bucket-01/repo: error talking HTTP to rclone: Get \"http://localhost/file-<n>\": context deadline exceeded (Client.Timeout exceeded while awaiting headers)"}`.

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
   system trust store, install the CA bundle as root (the file adds the operator
   CA to the system store for Restic and Rclone; it does not narrow trust):
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

- `PLUTON_AGENT_STORAGE_CA_FILE` adds the operator CA for S3 connections; it does
  not narrow trust (Go still loads `/etc/ssl/certs`).
- One shared HCP key covers the whole namespace: a compromised Agent host can
  delete other plans' S3 data (risk accepted by the operator).
- The classification follows the Restic 0.19.1 and Rclone 1.75.1 output captured
  above, plus Restic's exit codes, retry messages and backend error texts read
  from its 0.19.1 source (`cmd/restic/main.go`, `internal/global/global.go`,
  `internal/backend/rest`, `internal/backend/rclone`). A storage failure without
  provider text (for example a key revoked after the access check, which the
  Rclone bridge turns into a bare HTTP 500) stays `restic-backup-failed`. Restic
  retries a failing backend call for about 15 minutes and then retries its lock
  refresh and unlock, so a storage outage during a backup is reported only after
  about 20 to 35 minutes (measured in the lab and the captures). A run against an
  endpoint that answered 503 to every request had not exited after 35 minutes and
  was stopped.
- A storage endpoint that keeps failing until the Agent's own deadline (24 hours
  for a backup with a database job), or until the backup is killed or cancelled,
  is reported as `restic-backup-failed` (or `cancelled`), not as a storage code:
  the deadline is never classified, so that a source read hung on an NFS hard
  mount is never reported as storage. An S3 backup without a database job has no
  Agent deadline, so a run that Restic keeps retrying stays running until it is
  cancelled. Stage 3 failover must not rely on the failure code for these cases.
- Within the last 64 KB, authentication beats access beats transport: a recovered
  403 retry close to a final transport failure reports access.
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
`agent/src/inventory.test.ts`, `agent/src/operationalHardening.test.ts`,
`agent/package.json`, `package.json`,
`agent/examples/pluton-agent.env.example`, `contracts/standalone-source-v1.json`,
`contracts/v0.8.0.json` (new), `scripts/tests/contracts.test.mjs`,
`scripts/tests/runtime-pins.test.mjs`, `scripts/tests/release.test.mjs`,
`scripts/package-release.mjs`, `scripts/verify-release.mjs`,
`installers/install-agent.sh`, `installers/tests/install-agent.test.sh`,
`tests/post-dump/Dockerfile`, `tests/post-dump/native.lab.ts`, `README.md`,
`docs/OPERATIONS.md`, `docs/COMPATIBILITY.md`, `docs/S3_REPOSITORY.md` (new).
