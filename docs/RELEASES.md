# Agent-only immutable releases

This repository prepares releases but never publishes automatically. Version tags,
GitHub publication/organization transfer, signing policy and production activation
are human-approved operations. CI has contents:read only and no upload/release/
registry/deploy step. No long-lived GitHub token is needed by a public source host.

## Build and inspect

Use a clean committed Linux checkout with approved private Node 22.23.4 and frozen
pnpm 10.20.0 dependencies. Run typecheck, Agent tests, contracts, installer safety
and isolated Ubuntu validation first.

The [Ubuntu matrix](UBUNTU_VALIDATION.md) covers both pinned 22.04 and 24.04
userlands, including repeated reproducible packaging. A release manifest for
linux-x64 is not a native OS acceptance certificate; review the pending
[native VM gate](NATIVE_SYSTEMD_ACCEPTANCE.md) and exact target point release.
Independent [network/enrollment changes](NETWORK_ENROLLMENT.md) retain protocol
0.7.0 but require their new reviewed source commit and explicit source hash delta.
Regenerate commands pinned to the older source; never overwrite an immutable
release tag/asset to deliver changed bytes.

Then build from the clean reviewed checkout:

```sh
corepack pnpm package:release
(cd release && sha256sum -c SHA256SUMS)
node scripts/verify-release.mjs release
```

Packaging rebuilds TypeScript into a fresh disposable directory with the pinned
5.9.3 compiler, refuses dirty/uncommitted or changing source, rejects links/special
files, excludes tests from the app archive and uses fixed source-commit tar times,
numeric ownership, modes/order and gzip bytes. Repeated packaging of the same
source/lock/toolchain is checked for identical manifest/artifact hashes on Linux.

Output in ignored `release/`:

- `pluton-agent-v0.7.0-source.tar.gz`: complete tracked source, installer and docs.
- `pluton-agent-v0.7.0-linux-x64-app.tar.gz`: application-only review artifact,
  build identity/source SHA, checksums and attribution; no runtime/state/identity.
- `release-manifest.json`: full source commit, version, architecture/toolchain,
  compatibility identity and both exact archive SHA-256 digests.
- `SHA256SUMS`: archive and manifest digests.

A checksum fetched from the same untrusted location is not authenticity proof.
Review exact source SHA, CI/provenance and artifact SHA through an approved trust
channel before use. No floating latest/main authorization is implied. Private
Node/Restic/Rclone are provisioned by the source installer with existing pins;
no unreviewed bundled executable or npm install script is activated from an archive.

The source archive supports a **fresh** build/install without monorepo or Git
history. The app archive is not an alternate updater and must never be copied over
an installed app to evade transaction/health checks. The current standalone upgrader
requires a clean **Git checkout** of this Agent repository to archive the reviewed
commit. Upgrade from release archives alone is not yet implemented; document that
limit rather than weakening committed-source checks. Installed provenance retains
format=1 content/source fingerprints and a standalone distribution marker; release
manifests bind those source deliveries to the new repository's own commit.

The [Node 22.23.4 security patch](NODE_RUNTIME_SECURITY.md) describes private
runtime upgrade, state preservation, rollback and the Server commit-pin/wizard
update required before distributing new installation commands.

## Host pinning and future private organization

Hosts should check out an approved full SHA or verify an immutable reviewed tag
and record its resolved SHA. Fetching refs is not permission to upgrade. Review
server compatibility and drain before every activation. Keep exact prior app,
receipt and source/artifact identities for rollback. Do not delete history or
reuse a version tag for changed bytes.

For a future private GitHub Organization, transfer the Agent repository through
reviewed organization ownership/access policy. Update documentation and enrollment
UI templates in a separately reviewed server change; do not rewrite installed
identity/server origin or automatically retarget trust. Prefer approved artifact
distribution with verifiable checksums/provenance to permanent GitHub credentials
on source hosts. Private download transport/authentication is NOT implemented here;
define short-lived delivery outside chat/Git before using a private release source.

Operator signing/provenance publication, real hosted CI and production upgrade
acceptance remain separate gates. A local package, draft CI workflow or mock API
is not production release approval.
