#!/usr/bin/env bash
# Actual Node acquisition, then synthetic Restic DNS failure before activation.
set -Eeuo pipefail
[[ -f /opt/pluton-disposable-ubuntu-test && ${PLUTON_DISPOSABLE_INSTALL_TEST:-} == 1 && $EUID == 0 ]] || exit 90
[[ ! -e /opt/pluton-agent && ! -e /var/lib/pluton-agent && ! -e /etc/pluton-agent.env ]] || exit 91
! getent passwd pluton-agent >/dev/null || exit 92
mkdir -p /srv/example-app /run/systemd/system
private=$(mktemp -d /tmp/pluton-download-failure.XXXXXXXX)
trap 'rm -rf -- "$private"' EXIT
printf 'synthetic-token-never-used\n' > "$private/token"
if (
	source installers/install-agent.sh
	curl() {
		if [[ "${!#}" == "$RESTIC_RELEASE_BASE/restic_${RESTIC_VERSION}_linux_amd64.bz2" ]]; then
			printf 'attempt\n' >> "$private/attempts"
			printf 'synthetic-token-never-used curl error detail\n' >&2
			return 6
		fi
		command curl "$@"
	}
	# Timing/backoff is separately asserted; avoid real waits for injected DNS.
	sleep() { printf '%s\n' "$1" >> "$private/backoff"; }
	main --server https://localhost:18443 --allowed-root /srv/example-app --token-stdin
) < "$private/token" > "$private/failure.log" 2>&1; then exit 93; fi
[[ $(wc -l < "$private/attempts") == 4 && $(cat "$private/backoff") == $'2\n4\n8' ]]
grep -F 'Dependency Restic GET attempt 4/4: DNS resolution failed.' "$private/failure.log" >/dev/null
grep -F 'Preparation failed before activation' "$private/failure.log" >/dev/null
! grep -F synthetic-token-never-used "$private/failure.log" >/dev/null
for final in /opt/pluton-agent /etc/pluton-agent.env /var/lib/pluton-agent /etc/systemd/system/pluton-agent.service; do
	[[ ! -e "$final" && ! -L "$final" ]] || exit 94
done
[[ -z $(find /opt -maxdepth 1 -name '.pluton-agent-stage.*' -print -quit) ]]
! getent passwd pluton-agent >/dev/null || exit 95
bash install-agent.sh --check --server https://localhost:18443 --allowed-root /srv/example-app >/dev/null
printf 'PASS actual verified Node download followed by bounded Restic DNS failures leaves no final app/config/state/unit/account; fresh preflight still passes\n'
