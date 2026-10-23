# Agent 0.7.1 source access diagnostics

This is an independently reviewed standalone Agent patch. It needs the matching
Server diagnostics patch for path visibility. It does not change the monorepo
Agent, source access grants, permissions, exclusions, retention or Legacy access.
No rollout or production access was performed.

## Why paths were lost

The Agent already classified structured Restic source failures, but returned only
`source-entry-inaccessible` or `source-missing`. `SourceAccessError` wrapping also
discarded entry details. The Server cannot reconstruct a path that the Agent
never reported. Raw provider stderr must remain private.

`sourceDiagnostics.ts` now extracts only contained relative names from JSON source
error records and closed OS categories. The runner collects records from stderr
and stdout, including fragmented and final unterminated lines. Restic entries
have type `unknown`; file type is not inferred from the name. Safe entry types
from metadata checks are available for bounded preflight failures.

`filesystemPolicy.ts` can collect multiple failures within its existing bounded
v4 backup checks when diagnostics were negotiated. Exclusions still run before
lstat/access/traversal; excluded subtrees never appear as inaccessible. Nested
symlinks are not followed. There is no new recursive scan on inventory, polling
or UI reads, and the existing explicit CLI retains its first-error behavior.

## Contract and compatibility

Agent version is 0.7.1. Payload versions 1–4 remain supported. The optional
`sourceDiagnosticsVersion: 1` field must appear inside the Server-signed command
to opt in. Only then can `runtime.ts` include optional `sourceDiagnostics` in a
failed completion. `client.ts` signs the exact body with the existing HMAC and
lease fields. Old Servers never request this field, and their completion shape
remains unchanged. No new capability is advertised to strict old inventories.

An illustrative optional field is:

```json
{
  "sourceDiagnostics": {
    "version": 1,
    "origin": "restic",
    "problemCount": 1,
    "countIsLowerBound": true,
    "entries": [
      {
        "relativePath": "app/logs/id_rsa",
        "entryType": "unknown",
        "errno": "EACCES",
        "excluded": false
      }
    ]
  }
}
```

This is synthetic metadata, not file content. The Server validates and stores
the extension separately from generic errors. It must not copy path data into
notifications, public logs, telemetry or generic command errors.

There are at most 20 representative entries, each name at most 512 UTF-16 units.
Counts are bounded observations and explicitly lower bounds: unreadable subtrees,
resource limits and repeated Restic reports prevent a complete distinct-file
inventory. `.` means the selected source root. Unsafe names are omitted, not
truncated or substituted with an invented path. Controls/newlines, HTML,
malformed Unicode, direction overrides, excessive combining marks, absolute
paths/traversal, credential assignments and PEM markers are withheld.

Only observed error categories are returned. `EACCES`/`EPERM` indicate access
failure; `ENOENT` means missing/disappeared and can be transient. Unknown errors
remain generic. Source JSON errors fail the backup even with a contradictory
zero exit code. The extension cannot turn a failure into success. The existing
protected durable completion receipt retains diagnostics for retry after a lost
completion response; logs still contain only generic stage/code messages.

The independent source baseline explicitly records every changed runtime/test
file and Agent release version. The immutable extraction manifest and original
0.7.0 HMAC/exclusion fixtures remain unchanged. Contract tests assert 0.7.1 release
identity and the original signatures, rather than weakening runtime/provenance
pins.

## Preflight audit and operator actions

Source Access Validate checks selected roots and authorization state. It is not
a saved-plan recursive scan and has no plan exclusion receipt. No new remote
scan command or general directory browser is introduced. A future explicit
remote preflight needs a separately scoped signed command, immutable source and
exclusions, durable progress/cancellation, concurrency/resource bounds, no hooks,
no dumps, no snapshot, and no access approval mutation.

For an explicitly authorized local read-only check, use the existing CLI as the
backup service identity and pass the exact approved source and saved exclusions.
See [operations](OPERATIONS.md). Its scan remains capped at 10,000 included
entries and five seconds; partial results do not prove full coverage. There is
no automatic chmod, ownership/ACL change, source edit, root broadening or exclusion.
Sensitive names such as `id_rsa` require operator review, not automatic access.

## Validation and rollback

Use Node 22.23.4 and pnpm 10.20.0 with the frozen lockfile. Relevant checks are
`pnpm typecheck`, `pnpm test`, `pnpm validate:standalone`, `pnpm test:contracts`,
`pnpm test:installers`, and `git diff --check`. Run Linux permission tests as a
non-root account; Windows skips are insufficient evidence. Results and exact
local commit IDs are recorded in the final task report. Disposable Ubuntu tests
use synthetic fixtures and mock control-plane/process boundaries; they do not
prove production systemd integration or authorize deployment.

Validation on 2026-10-23 used cached Ubuntu 22.04 and 24.04 images with external
network disabled. On each: typecheck passed; 191 unit tests passed with no skips;
the 43-file independent source baseline passed; nine contract tests passed; the
installer shell checks and 70 upgrade tests passed. Frozen-lockfile validation
and `git diff --check` passed. The source archive retained Git executable modes;
Windows filesystem modes alone were insufficient for installer execution. The
Server's 3,878 passing backend tests and 44 passing frontend tests are documented
with its patch; its existing frontend ESLint configuration fails before file
analysis, independently of this Agent patch.

Base revision: `eed957e`. Feature branch: `codex/source-access-diagnostics` in the
separate Agent repository. Exact final commit IDs are in the final task report.

Roll out the Server before Agent 0.7.1. Verify a disposable old Agent and one new
Agent before authorizing a wider rollout. To roll back, pause/drain jobs and
completion deliveries first, restore the previously approved immutable Agent
artifact through the existing upgrade/rollback procedure, then restore the old
Server. A diagnostic completion would be rejected by an old strict Server; drain
it before reverting. Never delete identity/receipts to force execution. No SQLite
migration, environment setting or credential change is required.
