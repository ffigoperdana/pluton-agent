#!/usr/bin/env bash
# Synthetic curl faults; production URLs/pins are never modified by the installer.
set -Eeuo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/../install-agent.sh"
download_test_root=$(mktemp -d "$REPOSITORY_ROOT/.pluton-agent-test.download.XXXXXXXX")
trap 'rm -rf -- "$download_test_root"' EXIT

curl() {
	[[ "$1" == --disable ]] || return 99
	local output='' maximum='' url='' item count code status
	while (($#)); do
		case "$1" in
			--disable|--silent|--fail|--location) shift ;;
			--proto|--proto-redir) [[ "$2" == '=https' ]] || return 99; shift 2 ;;
			--request) [[ "$2" == GET ]] || return 99; shift 2 ;;
			--max-redirs) [[ "$2" == 5 ]] || return 99; shift 2 ;;
			--retry) [[ "$2" == 0 ]] || return 99; shift 2 ;;
			--connect-timeout) [[ "$2" == 30 ]] || return 99; shift 2 ;;
			--tlsv1.2) shift ;;
			--max-time) maximum="$2"; (( maximum > 0 && maximum <= 120 )) || return 99; shift 2 ;;
			--output) output="$2"; shift 2 ;;
			--write-out) [[ "$2" == '%{http_code}' ]] || return 99; shift 2 ;;
			https://*) url="$1"; shift ;;
			*) return 99 ;;
		esac
	done
	[[ -n "$output" && -n "$url" && -n "$maximum" && ! -e "$output" ]] || return 99
	count=$(cat "$case_root/count"); count=$((count + 1)); printf '%s' "$count" > "$case_root/count"
	printf '%s\n' "$maximum" >> "$case_root/budgets"
	item=$(sed -n "${count}p" "$case_root/sequence"); code=${item%%:*}; status=${item#*:}
	printf '%s' 'synthetic-interrupted-bytes' > "$output"
	if [[ "$code" == 0 ]]; then printf '%s' 'synthetic-complete-payload' > "$output"; fi
	printf 'synthetic-token-must-not-log' >&2
	printf '%s' "$status"
	return "$code"
}
sleep() { printf '%s\n' "$1" >> "$case_root/backoff"; }

new_case() {
	case_root=$(mktemp -d "$download_test_root/case.XXXXXXXX")
	printf 0 > "$case_root/count"
	printf '%s\n' "$@" > "$case_root/sequence"
}
assert_clean_failure() {
	[[ ! -e "$case_root/artifact" && ! -e "$case_root/artifact.part" ]]
	! grep -F 'synthetic-token-must-not-log' "$case_root/log" >/dev/null
}

# DNS, timeout, partial-file, refused connection, reset/empty reply and HTTP/2 faults.
for code in 5 6 7 18 28 52 55 56 92; do
	new_case "$code:000" '0:200'
	download_dependency restic "$case_root/artifact" > "$case_root/log"
	[[ $(cat "$case_root/count") == 2 && $(cat "$case_root/backoff") == 2 ]]
	[[ $(cat "$case_root/artifact") == synthetic-complete-payload && ! -e "$case_root/artifact.part" ]]
	! grep -F 'synthetic-token-must-not-log' "$case_root/log" >/dev/null
done
printf 'PASS dependency GET recovers from nine transient curl failures without appending partial bytes\n'

for status in 408 429 500 502 503 504; do
	new_case "22:$status" '0:200'
	download_dependency rclone "$case_root/artifact" > "$case_root/log"
	[[ $(cat "$case_root/count") == 2 ]]
done
for failure in 22:401 22:403 22:404 60:000 77:000 23:000 35:000 1:000; do
	new_case "$failure"
	if download_dependency node "$case_root/artifact" > "$case_root/log"; then exit 1; fi
	[[ $(cat "$case_root/count") == 1 && ! -e "$case_root/backoff" ]]
	assert_clean_failure
done
printf 'PASS transient HTTP retries; certificate/configuration, local IO and permanent HTTP failures do not retry\n'

new_case 6:000 6:000 6:000 6:000
if download_dependency node-checksums "$case_root/artifact" > "$case_root/log"; then exit 1; fi
[[ $(cat "$case_root/count") == 4 && $(cat "$case_root/backoff") == $'2\n4\n8' ]]
assert_clean_failure
printf 'PASS retry count and exponential backoff are bounded\n'

# Move the clock only in this subshell, simulating time spent in failed curl.
(
	new_case 28:000 28:000
	log() { SECONDS=$((SECONDS + 301)); }
	if download_dependency node "$case_root/artifact" > "$case_root/log"; then exit 1; fi
	[[ $(cat "$case_root/count") == 1 && ! -e "$case_root/backoff" ]]
	assert_clean_failure
)
(
	new_case 28:000 60:000
	log() { if [[ "$*" == *'attempt 1/4'* ]]; then SECONDS=$((SECONDS + 245)); fi; }
	if download_dependency node "$case_root/artifact" > "$case_root/log"; then exit 1; fi
	[[ $(sed -n 1p "$case_root/budgets") == 120 && $(sed -n 2p "$case_root/budgets") -le 55 ]]
)
printf 'PASS total time budget bounds retries and reduces the next transfer allowance\n'

new_case
if download_dependency 'https://example.invalid/enroll?token=synthetic-private' "$case_root/artifact" > "$case_root/log"; then exit 1; fi
[[ $(cat "$case_root/count") == 0 ]]
! grep -F synthetic-private "$case_root/log" >/dev/null
printf 'preserved' > "$case_root/artifact"
if download_dependency restic "$case_root/artifact" > "$case_root/log"; then exit 1; fi
[[ $(cat "$case_root/artifact") == preserved && $(cat "$case_root/count") == 0 ]]
printf 'PASS helper refuses arbitrary/token URLs and existing destinations\n'

for dependency in node backup; do
	new_case 0:200 0:200
	if (
		TEST_MODE=0
		INSTALL_PARENT="$case_root"
		INSTALL_ROOT="$case_root/final"
		CONFIG_FILE="$case_root/config"
		STATE_DIR="$case_root/state"
		SYSTEMD_UNIT="$case_root/unit"
		create_stage_root
		tar() { touch "$case_root/extracted"; return 99; }
		bzip2() { touch "$case_root/extracted"; return 99; }
		unzip() { touch "$case_root/extracted"; return 99; }
		if [[ "$dependency" == node ]]; then prepare_private_node_runtime
		else prepare_private_backup_binaries; fi
	) > "$case_root/log" 2>&1; then exit 1; fi
	grep -F 'checksum verification failed' "$case_root/log" >/dev/null
	[[ ! -e "$case_root/extracted" && -z $(find "$case_root" -name '.pluton-agent-stage.*' -print -quit) ]]
	assert_clean_failure
done
printf 'PASS downloaded checksum mismatches never reach extraction; private scratch is removed\n'

python3 "$REPOSITORY_ROOT/installers/tests/dependency-https.py"
printf 'PASS: dependency downloader tests\n'
