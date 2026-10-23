# Signed API compatibility and stuck command recovery

## Confirmed cause and scope

The standalone 0.7.0 client required a result property on every signed success.
The reviewed Server returns only {"success":true} for ACK, events and completion.
A real synthetic HTTP ACK reproduces INVALID_RESPONSE before this patch. The
Agent therefore stops before its accepted event or command execution. Events
and completion had the same mismatch even if ACK were bypassed. Nothing should
bypass ACK.

This confirms a source-level interoperability defect, consistent with the
reported 200/16-byte responses. Production response bodies, installed artifact
provenance and individual command state were not inspected. Those observations
alone cannot prove that a particular backup never executed.

Only Agent response parsing changes. Runtime capability/protocol and package
version remain **0.7.0**. Identify this fix by its reviewed full Git SHA, not that
unchanged version string. HMAC input, nonce generation, identity, TLS, signed
commands, leases, execution, cancellation, roots and receipts are unchanged.
No dependency, installer, Server, proxy or enrollment schema change is required.

## Exact Server contracts

Paths below are POSTs. The local Server source inspected was commit
0c0b29e7f312aeb37a8ed5f6ede099f5c953d668; this is not proof of the deployed Server SHA.
Authority: Server backend/src/controllers/AgentController.ts and
backend/src/services/AgentService.ts. Standalone agent/src/client.ts validates
these responses; agent/src/transport.ts preserves non-2xx, JSON, size, timeout,
origin and verified TLS boundaries.

| Endpoint | HTTP | Success JSON | Agent validation |
| --- | --- | --- | --- |
| /api/agent/enroll | 201 | {success:true,result:{deviceId,agentId,secret,pollIntervalSeconds}} | Required object, nonempty bounded strings, positive integer interval |
| /api/agent/heartbeat | 200 | {success:true,result:AgentPublic} | Required object; returned inventory is not authority or execution input |
| /api/agent/poll | 200 | {success:true,result:{command:null}} or signed command | Explicit null or complete typed envelope followed by signature/expiry verification |
| /api/agent/commands/:id/ack | 200 | {success:true} | Boolean true; no result required |
| /api/agent/commands/:id/events | 200 | {success:true} | Boolean true; no result required |
| /api/agent/commands/:id/complete | 200 | {success:true} | Boolean true; no result required |
| /api/agent/commands/:id/status | 200 | {success:true,result:{cancelled:boolean}} | Required object and actual boolean |

AgentPublic includes agentId, deviceId, status, hostname, os, architecture,
agentVersion, optional tool versions, capabilities, lastSeen and createdAt.
Unused heartbeat fields are not interpreted as permissions. Void responses may
contain additive fields from compatible Servers; these are ignored, never used
as command data. Success missing/false/null/string, primitives, arrays, empty,
HTML, malformed JSON, unsupported 204, redirects and non-2xx are rejected.
Enrollment/poll/status do not inherit void semantics. Poll no longer mistakes a
missing command or false/zero command for an empty queue. Diagnostics remain
closed categories, never response bodies, credentials or lease tokens. Requests
are not automatically retried after ambiguous responses.

## Lease and receipt findings

Server backend/src/stores/AgentStore.ts::leaseNext uses a 60-second lease
(backend/src/types/agents.ts). ACK sets acknowledged without extending it.
Nonexpired leased/acknowledged/running work blocks another command for that
Agent. Subsequent poll returns command:null. On a later poll an expired lease
is requeued and the same command gets a fresh token/signature; this does not
create another backup job. Signed status/progress renew an executing lease.
For active commands, a duplicate ACK with the live token is idempotent and
expired/wrong tokens refuse. The Server also returns an existing completed/failed
row for terminal ACK idempotency; it does not create a lease or requeue that row.
Do not infer these Server guarantees from the scripted Agent test alone.

Agent agent/src/runtime.ts ACKs before accepted/event/execution. An invalid or
lost ACK response exits without executing. It never resends ACK internally.
After completion, identity stores a bounded (100-entry) completion receipt
before delivery. A later dispatch of that command resends its receipt without
ACK/execution. Existing backupFilesystem.ts also checks exact tagged snapshot
identity before another backup when a local receipt is unavailable. Do not
clear receipts, staging evidence or repository locks. Do not extrapolate these
regressions to arbitrary power-loss exactly-once guarantees: receipt eviction,
uncertain repository writes or interrupted execution require individual review.

### Backup recovery: synthetic example app-01

1. Pause new plans for this Agent using the normal authenticated Server UI.
   Do not create repeated Run Now jobs while one is queued.
2. Privately correlate the exact device, plan, backup and command IDs. Check
   Server state, bounded Agent journal, current child processes/cgroup, private
   job workspace and snapshot/receipt evidence. Zero UI bytes alone is not proof
   of no activity. Do not print identity/config contents.
3. If ACK-response failure is proven to have prevented execution, an operator
   may cancel that exact stuck backup using its existing authenticated Cancel
   action. Server RemoteBackupService.cancelBackup verifies plan/backup binding
   and cancels its command; the backup becomes cancelled. If a process actually
   runs, cancellation is cooperative through signed status: wait for it to exit
   and for local drain, not just UI cancellation. No cancellation was performed
   by this patch.
4. With no running job and no uncertain snapshot, upgrade through the fenced
   standalone procedure below. Confirm the old command is terminal before one
   separately approved replacement backup. Never replay an uncertain success.
   Alternatively keep the same authorized job for re-lease only after exact
   state review; no new job is necessary merely because a lease expired.

### Source Access recovery: synthetic example app-02

Server AgentSourceAccessService and AgentSourceAccessStore bind request/command
and reports to the enrolled Agent. markDelivered changes queued to validating
before ACK, so a stale UI can still say Queued after command delivery. A healthy
heartbeat alone cannot finish validation. Completion checks lease, request,
policy revision and signed result together. Validation reports approved,
pending-host-approval or rejected paths; it does not apply a selection or grant
host rights. Both authorization modes retain host policy/delegation boundaries.

1. Pause new requests for this device; inspect the exact request kind and state.
   Cancelling app-01's backup cannot cancel app-02's Source Access request.
2. Existing Source Access Cancel is limited to queued/pending-host-approval
   requests with queued/failed commands (AgentSourceAccessStore.cancel).
   A delivered validating/acknowledged request is **not cancellable by that API**.
   Do not force it through, reset its row or clear the Agent's state.
3. For a proven ACK-only, nonexecuted validation, leave the existing authorized
   request intact. Verify local idle/drain and no selection/mode setup
   transaction, then use the upgrader's hold. Its health check only heartbeats.
   After safe activation the next eligible poll can re-lease the same expired
   command; the fixed Agent validates and completes it. Refresh Source Access
   history and verify the request's result and unchanged effective roots before
   creating a Plan or another request. Do not turn this into an APPLY request.
4. Ordinary validation/APPLY requests have no generic wall-clock terminal expiry
   in reconcileTerminalRequests: lease expiry requeues the command, not the
   request. Mode setup has its own signed expiry plus skew. Stale revisions can
   be explicitly rejected at delivery. Terminal cancellation/failure is reconciled
   on the per-device Server request read/create paths.
5. If it cannot settle after a healthy fixed Agent poll, or execution/policy state
   is uncertain, STOP for a separate Server/host investigation. An offline Agent
   with a delivered validating request can remain blocked. A separate Server
   enhancement could provide ownership- and lease-aware stale validation
   cancellation/reconciliation, with concurrent delivery/completion tests; it is
   not implemented or required to repair this ACK contract. No automatic expiry
   of unknown applied changes or authorization bypass is proposed.

## Reviewed rollout and rollback (operator only)

These instructions do not authorize production execution. app-01/app-02 are
synthetic roles, not host names to target. Publish/review the local fix manually,
wait for exact-final-commit Linux CI and obtain deployment approval. Record the
final merged 40-hex SHA and compare the checkout to it; do not use a moving tag.
For new enrollment only, the Server's AGENT_INSTALL_COMMIT may then reference
that reviewed Agent commit. Changing it does not update enrolled Agents.

For each existing **standalone** installation separately, after the role-specific
review above and verified local idle state:

~~~sh
cd /srv/example-agent-checkout
git fetch origin main
AGENT_SOURCE_SHA='REPLACE_WITH_REVIEWED_40_HEX_SHA'
printf '%s\n' "$AGENT_SOURCE_SHA" | grep -Eq '^[0-9a-f]{40}$'
git checkout --detach "$AGENT_SOURCE_SHA"
test "$(git rev-parse HEAD)" = "$AGENT_SOURCE_SHA"
test -z "$(git status --porcelain)"
sudo bash upgrade-agent.sh --check
# Review the preflight; run only with separate deployment authorization:
sudo bash upgrade-agent.sh
systemctl is-active pluton-agent.service
/opt/pluton-agent/runtime/bin/node --version
~~~

Do not use install-agent.sh, re-enroll, revoke, rotate secrets, edit provenance,
clear leases or force-delete fences. The upgrader checks ownership/provenance,
builds with private Node/Corepack/pinned pnpm, verifies drain/preserved hashes,
backs up and atomically publishes artifacts while stopped, and health-checks
before releasing its hold. It refuses active jobs, pending policy transactions,
unknown locks or changed state. Do not stop a running backup to bypass refusal.
The old monorepo Agent is outside this path and must not be migrated here.

Confirm exact new source commit in protected upgrade provenance/receipt, stable
service, same enrolled device/Agent identity and unchanged config/roots/policy
without displaying their secrets. Confirm authenticated heartbeat and one
approved command advancing ACK/events/completion. Check app-02 validation and
unchanged grants first; run app-01's single replacement backup only after the
old job is terminal and uncertainty is resolved. Resume schedules gradually.

For an upgrade failure, preserve its private receipt and respect automatic
rollback diagnostics. For explicit rollback keep plans drained, prove no active
execution or policy transaction, review the exact transaction ID and use:

~~~sh
sudo bash upgrade-agent.sh --rollback <exact-upgrade-id>
systemctl is-active pluton-agent.service
~~~

See [upgrade safety](AGENT_UPGRADE.md). A manual rollback after normal work may
refuse because identity/receipts have changed; do not overwrite them to force it.
Rollback to the previous ACK-broken app restores artifacts, not functionality;
keep relevant plans paused. No real systemd, production pairing, real database,
SFTP/HCP storage or power-loss recovery is certified by synthetic tests.
