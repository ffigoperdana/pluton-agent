# Installation and operation

## Preconditions and trust

Use a new Ubuntu 22.04 x86_64 source host with systemd as its active service manager.
Ubuntu 24.04 x86_64 is a validation candidate using the same clean-install steps;
native VM acceptance is pending. Review [OS results](UBUNTU_VALIDATION.md) and the
[native acceptance gate](NATIVE_SYSTEMD_ACCEPTANCE.md) before onboarding.
The standalone upgrader also requires unified cgroup v2 and the standard installer
paths. Reserve measured disk for private Node/Corepack, source compilation, app,
backups and job workspaces. Existing upgrader minimum admission is 2 GiB plus two
combined app/runtime sizes; dependency downloads/history can need more. No Docker is needed on the
Agent host. Docker in this repository is only a disposable development test.

Required utilities include Bash, Git, curl, CA certificates, xz/tar, bzip2, unzip,
coreutils/findutils, runuser, passwd/account tools and systemctl. Verify these with
the infrastructure owner rather than replacing system Node. The installer checks
the OS, architecture and utilities before provisioning.

For a clean disposable host of either target release, provision prerequisites:

```sh
sudo apt-get update --error-on=any
sudo apt-get install --no-install-recommends ca-certificates curl git xz-utils \
  bzip2 unzip coreutils findutils util-linux passwd systemd gawk grep sed tar
```

Python, pip, Docker and global Node/pnpm are not Agent installation prerequisites.
The synthetic validation suite additionally uses Python3, OpenSSL, ACL tools and
locales. Do not install a database server to satisfy a synthetic test.

Follow README's reviewed immutable checkout, run `bash install-agent.sh --check`
with the same server/allowed roots/optional CA, then run the privileged fresh
installer and enter the one-time token at its private prompt. Preflight runs
without root, network, credentials or filesystem/service changes. It validates
local prerequisites only, not remote TLS or future service-user access.

Pin the reviewed source commit as shown in README. The checkout and download chain
must be trusted before running a root script. Review CI for that exact commit.
Restic 0.19.1 and Rclone 1.75.1 have embedded SHA-256 pins; Node v22.23.4 is verified
against its version-specific HTTPS SHASUMS256 index and embedded reviewed archive
SHA-256. See [the runtime patch and operator checks](NODE_RUNTIME_SECURITY.md).
This does not claim a detached
signature check that the current installer does not implement. The application
uses no runtime npm packages; build dependencies are frozen in the minimal lockfile.
Pinned dependency GETs have bounded retries (4 attempts, 2/4/8-second backoff,
30-second connect, 120-second transfer and 300-second total per artifact).
Download/build failures before activation leave no final app/config/state/unit.
See the [download audit and recovery procedure](INSTALLER_DOWNLOADS.md); this retry
policy never applies to enrollment or requests containing a token.

## Enrollment and paths

If curl works but the private Node Agent fails, use the new source's explicit
[Node HTTPS network preflight and safe diagnostics](NETWORK_ENROLLMENT.md).
DNS family order or an HTTP 400 probe alone does not prove broken IPv6 or an
invalid enrollment token. The transport selects one verified connection before
credentials are sent and never retries an ambiguous enrollment HTTP request.
DNS may take up to 15 seconds within the shared 30-second total request deadline;
the three sequential `network-check` probes can take about 90 seconds. Candidate
TCP/TLS deadlines remain 5 seconds with a 250 ms IPv4/IPv6 stagger. Native resolver
work may finish later; a late result cannot send an enrollment request.
Keep `install-agent.sh --check` as the local-only no-network prerequisite check.

The compatible server administrator creates an enrollment token in **Sources →
Add Remote Machine** with narrowly approved roots. The server-generated monorepo
checkout/install URL is not automatically updated by this extraction. On a new
standalone host use this repository's reviewed installer and enter the token at
its secure prompt. Do not use an old generated clone command blindly.

The installer provisions a dedicated `pluton-agent` service account, private
`/opt/pluton-agent/{runtime,bin,app}`, `/etc/pluton-agent.env`, systemd unit and
`/var/lib/pluton-agent`. Config is root-private; identity and command receipts are
private state, not repository files. Back them up through an approved private
procedure. Do not copy an enrolled identity to a second host.

The service requires outbound HTTPS to the server; it opens no inbound Agent
listener. DNS, time synchronization, CA trust and the exact server origin matter.
The source machine needs its own connection to SFTP and any source DB. The server
also needs primary repository access; optional S3 replication belongs to the server.

`--ca-file` takes an approved PEM readable by the service. Do not disable certificate
validation or bypass origin checks. Existing mTLS configuration support is retained;
it is not configured automatically by enrollment. The token is consumed only during
initial enrollment, not stored in Git or used for upgrades.

Verify systemd status, authenticated ONLINE/Last seen, Agent version 0.7.0, private
client versions and required capabilities. `check` sends a signed heartbeat; it
does not poll or execute queued work. Never use `run --once` as an idle probe.
Systemd restart/stop commands below require operator drain/approval:

```sh
systemctl is-active pluton-agent
systemctl status pluton-agent --no-pager
journalctl -u pluton-agent --since '10 minutes ago' --no-pager
```

Review logs privately and sanitize paths, identities and credentials before sharing.

## Source Access and first backup

Enrollment roots are the host authority boundary. Switching to Server-Managed mode
still requires the exact one-time, revision/request/expiry-bound host delegation
command provided by the server. Pause/drain operations first. Then Validate paths,
inspect canonical previews, Apply validated paths and confirm effective roots.
Neither a pending UI request nor history retrieval grants access or modifies ACLs.

Linux traversal/read permissions are separate. Do not use chmod 777, recursive
ownership changes, broad roots, altered policy revision or receipt deletion as a
workaround. A local read-only scan uses only already authorized roots:

```sh
sudo -u pluton-agent /opt/pluton-agent/runtime/bin/node \
  /opt/pluton-agent/app/dist/index.js preflight \
  --source /srv/example-app --allowed-roots /srv/example-app --scan
```

A root-readable directory does not prove all included children are accessible;
bounded/partial scans are not full success. Source policy and protected-path checks
remain fail closed, including validation/apply, mode setup, leases and cancellation.

Create a Managed Agent Backup Plan on the server using a dedicated SFTP repository.
Keep source and repository disjoint; do not adopt a legacy repository through a
managed plan. Test one explicit synthetic backup. Check exact snapshot ID, receipt,
coverage, warnings and restored sample content. ONLINE and Complete are not proof
of SQL import, replica success or application recovery.

## Exclusions, DB and hooks

Agent 0.7.0 advertises `backupExclusionsVersion: 1`; configured exclusions require
backup envelope v4 and a compatible server. Bare `.git`, `.cache`, `node_modules`
match at any depth and are case-sensitive. `.cache` differs from `cache`; patterns
with `/` are source-relative. Only the tested relative grammar is supported, not
arbitrary Restic flags, shell expansion, traversal, absolute paths or negation.
Excluded subtrees are pruned before scanning; inaccessible included data still
fails. Generated SQL/metadata in separate lifecycle workspaces are protected.
Do not exclude sessions/uploads/vendor indiscriminately; owner-approved recovery
coverage is required.

MariaDB/MySQL/PostgreSQL dump clients are separately provisioned, root-protected
and constrained on the Agent; the installer does not install DB servers/clients.
Database & Hooks configuration lives on the server and approved host policy.
Up to eight configured dumps, engine/TLS/client restrictions, bounded bytes/time,
sanitized failures, cancellation and generated artifact SHA-256 remain intact.
Only approved host hooks may run, without browser-supplied shell commands or
elevation. Credentials flow through private approved mechanisms. Configuration,
successful dump, snapshot inclusion, SQL import and application recovery are
separate evidence. Stop on any missing required artifact.

Server-side recovery workers, Oracle MySQL Internal root operator, retained DB
Delete/TTL, resource guards and S3/HCP replication are not moved into this Agent.
No additional root recovery privilege is granted by extraction or enrollment.

## Upgrade, rollback and diagnostics

Use the detailed [standalone app/runtime upgrade contract](AGENT_UPGRADE.md) and
[compatibility boundaries](COMPATIBILITY.md). Fetch/review the exact approved Agent
commit, verify CI, pause server plans/Source Access requests and independently
drain operations. Then, for a standalone installation only:

```sh
sudo bash upgrade-agent.sh --check
sudo bash upgrade-agent.sh
systemctl is-active pluton-agent
```

`--check` is read-only local preflight, not server queue proof. Private toolchain
and root-protected config, identity, TLS, policy/receipts and unit must match. The
upgrader builds from this repository's own immutable Git commit, never the old
repository. It fences work, backs up and fsyncs, atomically replaces app only and
verifies health. Config/state/runtime are preserved; rollback files remain.

Canonical C collation is scoped to tree/source hash calculations; correctly
recorded C-format provenance remains valid. Locale mismatch is never repaired by
rewriting the accepted hash, resetting identity or re-enrolling. The additive
`distribution=pluton-agent-standalone-v1` marker identifies this distribution;
missing marker blocks the standalone upgrader. It is not a manual migration knob.

Failure output preserves Failed stage, Error code, Rollback and Previous Agent
preserved without dumping subprocess output or configuration. Rollback SUCCESS
still means upgrade failed. Preserve transaction evidence and pause jobs; do not
delete a lock/hold, transaction, policy, receipt or backup to retry uncertain work.
An explicitly reviewed rollback uses `sudo bash upgrade-agent.sh --rollback
<exact-upgrade-id>` after drain. It restores recorded app/runtime/provenance, not old state.

| Symptom                       | Safe investigation                                                                                                              |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| TLS/enrollment refusal        | Check origin, time, trusted CA, unexpired one-time token and correct server; never send token/logged identity to support        |
| ONLINE but backup unavailable | Inspect authenticated capabilities, configured roots and private binary versions; heartbeat alone is insufficient               |
| Source denied                 | Inspect canonical host-delegated/effective roots and service-account read-only scan; no broad permission relaxation             |
| Backup exclusions rejected    | Check server v4 and Agent capability 1; unsupported version must fail, never silently omit exclusions                           |
| BACKUP failure                | Preserve exact safe stage/code, check private disk/ownership/fsync evidence; identical copied bytes do not prove durable backup |
| PROVENANCE timeout/mismatch   | Dedicated bounded verification remains; inspect private receipts, locale-compatible fixed checkout, no accepted-record rewrite  |
| HEALTH_CHECK failure          | Inspect safe code, service stability and authenticated heartbeat; retain successful rollback and old Agent                      |
| Missing distribution marker   | Stop: legacy monorepo migration requires separate review, never hand-edit the record                                            |
| Unsupported OS/architecture | Only Ubuntu 22.04/24.04 x86_64 are installer targets; derivatives, other versions and ARM64 are refused. Check actual OS results before calling 24.04 supported. |
| Missing required utility | Install the named utility through approved Ubuntu packages; do not replace global Node/pnpm or bypass checks. |
| systemd/cgroup preflight fails | Require native systemd and unified cgroup v2. A container adapter is test-only; do not fake the service manager or disable AppArmor. |
| Existing state/unit/app refused | Use protected standalone upgrade, or separately reviewed migration. Do not delete identity/config to obtain a fresh-install PASS. |
| Failed fresh installation leaves private files | Preserve residuals. [Guarded recovery](INSTALLER_DOWNLOADS.md) accepts verified app/config plus EMPTY state, or legacy EMPTY state only with app/config absent, and no service/process. Independently confirm remote unenrolled status before quarantine. Any identity/temp/receipt/policy/lock refuses. |
| curl succeeds but Node times out | Compare explicit Node automatic/IPv4/IPv6 health probes and fixed DNS/connect/TLS/status classifications. Do not disable IPv6/TLS, force system-wide IPv4, or automatically retry a possibly consumed token. |
| Noble source permission denial | Inspect canonical parents, account groups and narrow read/traverse ACLs. New home permissions do not justify recursive chmod/chown. |

No production migration, service restart, storage mutation, automatic retention
cleanup or long-lived GitHub credentials are authorized by this guide.
