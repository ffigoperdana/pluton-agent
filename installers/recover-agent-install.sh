#!/usr/bin/env bash
set -Eeuo pipefail
recovery_script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
case "$*" in
	''|--check) recovery_action=check ;;
	'--quarantine --confirm-unenrolled') recovery_action=quarantine ;;
	--help|-h)
		printf '%s\n' 'Usage: sudo bash recover-agent-install.sh --check' \
		  '       sudo bash recover-agent-install.sh --quarantine --confirm-unenrolled' \
		  'Check is read-only. Quarantine preserves verified partial app/config/EMPTY state.' \
		  'Confirm the server did not enroll this host before quarantine/retrying. Any identity, state or unit refuses.'
		exit 0 ;;
	*) printf '%s\n' 'Invalid recovery arguments; no --force, token or arbitrary path is accepted.' >&2; exit 2 ;;
esac
[[ "$(uname -s)" == Linux && $EUID == 0 ]] || { printf '%s\n' 'Recovery requires Linux and root to inspect protected state.' >&2; exit 1; }
[[ -z "${PLUTON_AGENT_TEST_MODE:-}${PLUTON_AGENT_TEST_ROOT:-}${NODE_OPTIONS:-}${NODE_PATH:-}" ]] || exit 1
export PATH='/usr/sbin:/usr/bin:/sbin:/bin'
unset BASH_ENV ENV CDPATH
unset DBUS_SYSTEM_BUS_ADDRESS SYSTEMD_HOST SYSTEMD_MACHINE SYSTEMD_BUS_ADDRESS
source "$recovery_script_dir/install-agent.sh"
source "$recovery_script_dir/lib/recover-partial.sh"
configure_paths
validate_platform
command -v sync >/dev/null || fail 'Required utility is unavailable: sync'
if [[ "$recovery_action" == check ]]; then
	validate_partial_installation
	log 'PASS verified empty-state partial first install. No writes/network/service changes. Confirm remote enrollment outcome before explicit quarantine.'
else
	quarantine_partial_installation
fi
