# Debian 13 compatibility audit and validation

Agent version stays **0.9.0**: this change touches the installer allowlist, one test fixture and
the validation matrix, not the Agent runtime or its protocol. It uses only disposable synthetic
installations; no production host, Agent, token, policy or storage is involved.

## Verdict and evidence boundaries

Debian 13 (trixie) x86_64 passes the same isolated userland matrix as Ubuntu 22.04 and 24.04
(results below). A container build shares Docker's kernel, so it cannot certify a booted Debian
image, a Proxmox LXC container, kernel or AppArmor behaviour, or cgroup controller enforcement.
Native VM and LXC acceptance remain pending, as for Ubuntu 24.04
([native acceptance gate](NATIVE_SYSTEMD_ACCEPTANCE.md)).

## Source audit

| Area | Debian 13 finding | Decision and validation |
| --- | --- | --- |
| OS identification | `ID=debian`, `VERSION_ID=13` | Exact `debian:13` added to `validate_os_release`. No `ID_LIKE` fallback: Debian 11, 12, 14, point strings and derivatives (Raspbian, Mint, Pop!_OS, Kali) stay refused; installer tests assert this. |
| systemd / cgroup | systemd 257, unified cgroup v2 | Same unit and preflight. The real `systemd-analyze verify` of systemd 257 parses the generated unit; activation is simulated by the systemctl adapter, native activation pending. |
| glibc / binaries | glibc 2.41 | The pinned private Node 22.23.4, Restic 0.19.1 and rclone 1.75.1 run as the service account; real local Restic backup and restore fixtures pass. |
| Packages | Same utility package names as Ubuntu (`curl`, `git`, `xz-utils`, `bzip2`, `unzip`, `acl`, `systemd`) | No package or apt step in the installer; the test image installs the same list. |
| OpenSSL | OpenSSL 3.5 refuses a negative `-days` | Test fixture only: the expired-certificate test uses `-not_before`/`-not_after` when OpenSSL offers them (3.4 and later) and keeps `-days -1` on OpenSSL 3.0. Same assertion; source baseline updated with the reason. |
| Hardening | Same unit (`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=full`, empty capabilities) | Unchanged. In a Proxmox LXC container the namespaced settings need the container's nesting feature; a service that fails with `status=226/NAMESPACE` needs nesting enabled, never a weaker unit. |
| Upgrade | The upgrader has no OS check; it admits existing standalone layouts | No change. The `runtime-upgrade` target runs on Debian 13 in the matrix. |

## Reproduce

```sh
docker build --platform linux/amd64 --progress=plain --target validation \
  --build-arg TARGET_OS=debian-13 -f tests/ubuntu/Dockerfile \
  -t pluton-agent-validation:debian-13 .
docker build --platform linux/amd64 --progress=plain --target runtime-upgrade \
  --build-arg TARGET_OS=debian-13 -f tests/ubuntu/Dockerfile \
  -t pluton-agent-runtime-upgrade:debian-13 .
```

The base image is pinned by digest in `tests/ubuntu/Dockerfile`. CI runs the same targets for
`ubuntu-22.04`, `ubuntu-24.04` and `debian-13`.

## Results

Local Docker run on 2026-11-26 (Windows host, Docker Desktop, `linux/amd64`):

| Check | Debian 13 | Ubuntu 22.04 (regression) |
| --- | --- | --- |
| Userland | Debian GNU/Linux 13 (trixie), systemd 257, glibc 2.41, OpenSSL 3.5 | Ubuntu 22.04 |
| Download failures leave no partial install | PASS | PASS |
| Real fresh source build and install, TLS enrollment, signed heartbeat, reinstall refusal | PASS | PASS |
| Partial-install recovery and legacy provenance refusal | PASS | PASS |
| Agent test suite as an unprivileged account | 341 pass, 0 fail | 341 pass, 0 fail |
| Contract tests / installer tests | 15 / 79 pass, 0 fail | 15 / 79 pass, 0 fail |
| Standalone source parity (52 files, 41 explicit changes) | PASS | PASS |
| Reproducible release packaging and SHA-256 check | PASS | PASS |
| `runtime-upgrade`: 22.18.0 to 22.23.4, failed-start rollback, rename-gap recovery | PASS | not rerun |

The first Debian 13 run failed exactly one test, the expired-certificate fixture
(`openssl x509 -days -1` is refused by OpenSSL 3.5); the fixture change above fixed it with the
same assertion. The `network-routing` and post-dump targets were not run locally; CI runs them for
all three targets.
