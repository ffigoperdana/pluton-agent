# Pluton Linux Managed Agent

Standalone, outbound-only Linux Managed Agent for the open-source Pluton community
fork. Agent capability version **0.7.0**; target **Ubuntu Server 22.04 LTS,
x86_64, systemd and cgroup v2**. Ubuntu **24.04 LTS** passes disposable userland
validation; full native support awaits booted-VM acceptance.
See the [Ubuntu audit and test results](docs/UBUNTU_VALIDATION.md).
Apache-2.0 attribution is preserved in LICENSE and
NOTICE. This is an independently maintained extraction, not an upstream endorsement.

The repository contains no Pluton Server, frontend, database, Docker deployment or
runtime npm dependency. Its small `agent/` workspace deliberately preserves the
installer's tested app layout. Only TypeScript, Node type declarations and their
transitive type package are development dependencies.

```text
Administrator browser --> compatible Pluton Server (enrollment, signed queue, UI)
                                      ^
                                      | outbound verified HTTPS / authenticated Agent
                              Linux Managed Agent
                                | authorized source + constrained DB/hooks
                                +--> encrypted Restic backup --> SFTP primary
Server verifies primary, performs optional S3 replication and hosts recovery.
```

Start with [installation and operations](docs/OPERATIONS.md), then
[compatibility](docs/COMPATIBILITY.md), [upgrade/rollback](docs/AGENT_UPGRADE.md),
[releases](docs/RELEASES.md) and the [extraction audit/migration plan](docs/EXTRACTION_AUDIT.md).

## New host: clone only this repository

Choose a reviewed immutable source commit, not an implicit `latest`/moving main.
Replace the owner and SHA locally before running these example commands:

```sh
(
set -euo pipefail
git clone https://github.com/OWNER/pluton-agent.git
cd pluton-agent
AGENT_SOURCE_SHA='REPLACE_WITH_REVIEWED_40_HEX_SHA'
printf '%s\n' "$AGENT_SOURCE_SHA" | grep -Eq '^[0-9a-f]{40}$'
git checkout --detach "$AGENT_SOURCE_SHA"
bash install-agent.sh --check --server https://pluton.example.internal \
  --allowed-root /srv/example-app
sudo bash install-agent.sh --server https://pluton.example.internal \
  --allowed-root /srv/example-app
systemctl is-active pluton-agent
)
```

Create a one-time enrollment token using the compatible server's authenticated
Sources UI; enter it only in the installer's private terminal prompt. Do not put
it in Git, shell history, command arguments, screenshots or support logs. A private
CA is supplied with `--ca-file /path/to/approved-ca.pem`; TLS validation stays on.
The installer builds using its private Node/Corepack and pnpm **10.20.0**. No global
Node, npm or pnpm installation is required or replaced.

For curl/Node connectivity differences, explicit read-only Node HTTPS/family
diagnostics and enrollment failure categories, see
[network and enrollment troubleshooting](docs/NETWORK_ENROLLMENT.md).
`--check` remains local-only. The new `network-check` CLI sends unauthenticated
health GETs without reading a token or identity; HTTPS verification stays enabled.

`install-agent.sh` is **fresh-install only**. An existing installation, config or
identity is refused; it must not silently adopt a monorepo Agent. For an already
standalone installation use `sudo bash upgrade-agent.sh --check`, then the normal
app-only upgrade after drain and separate operational approval. Existing monorepo
Agents remain on their old upgrade path until a reviewed migration is available.
An identity-less failed first installation may qualify for the separate guarded
`recover-agent-install.sh --check` and explicit private quarantine procedure in
the [recovery guide](docs/NETWORK_ENROLLMENT.md). Any identity/state/service
evidence refuses; there is no force-reinstall bypass or automatic enrollment retry.

## Developer checks

With private/approved Node 22.18.0 and Corepack, use the exact packageManager pin:

```sh
corepack pnpm install --frozen-lockfile --ignore-scripts
corepack pnpm typecheck
corepack pnpm test
corepack pnpm test:contracts
corepack pnpm test:installers
corepack pnpm validate:standalone
```

Linux filesystem tests must run as an unprivileged account. The Agent-only Ubuntu
fixture provisions private pinned tools and synthetic DB/hook programs inside a
disposable container; it has no host mounts and never contacts real storage:

```sh
for version in 22.04 24.04; do
  docker build --platform linux/amd64 --progress=plain -f tests/ubuntu/Dockerfile \
    --build-arg UBUNTU_VERSION="$version" \
    -t "pluton-agent-validation:ubuntu-$version" . || exit
done
```

It exercises real source installation/build, TLS/HMAC enrollment against a local
synthetic API, the original Agent tests, upgrade rollback models, all three locales
and reproducible release packaging. **Systemd calls are explicitly adapted** in
the container; this is not proof of real systemd startup, cgroup admission, a
production server pairing, or a real database/SFTP/HCP recovery.
Use the [native systemd VM acceptance procedure](docs/NATIVE_SYSTEMD_ACCEPTANCE.md)
before claiming native Ubuntu 24.04 support or point-release certification.

GitHub CI validates only; it has read-only repository permissions and contains no
publishing, deployment, tag or release job. Publish/review this branch manually.
