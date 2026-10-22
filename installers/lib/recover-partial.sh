#!/usr/bin/env bash
# Shared guarded quarantine; source only after the reviewed installer helpers.

recovery_protected_path() {
	local entry="$1" expected_mode="${2:-}" owner=0 mode parent
	if is_test_mode; then owner="$(id -u)"; fi
	[[ -e "$entry" && ! -L "$entry" && "$(stat -c '%u' "$entry")" == "$owner" ]] || fail 'Partial installation is not root protected.'
	mode="$(stat -c '%a' "$entry")"
	(( (8#$mode & 0022) == 0 )) || fail 'Partial installation is writable by another account.'
	[[ -z "$expected_mode" || "$mode" == "$expected_mode" ]] || fail 'Partial installation has unsafe permissions.'
	parent="$(dirname "$entry")"
	while :; do
		[[ ! -L "$parent" && "$(stat -c '%u' "$parent")" == "$owner" ]] || fail 'Partial installation ancestor is not protected.'
		mode="$(stat -c '%a' "$parent")"; (( (8#$mode & 0022) == 0 )) || fail 'Partial installation ancestor is writable.'
		if is_test_mode && [[ "$parent" == "$PLUTON_AGENT_TEST_ROOT" ]]; then break; fi
		[[ "$parent" != / ]] || break
		parent="$(dirname "$parent")"
	done
}

validate_partial_installation() {
	[[ -d "$STATE_DIR" && ! -L "$STATE_DIR" &&
	   ! -e "$SYSTEMD_UNIT" && ! -L "$SYSTEMD_UNIT" ]] || fail 'Recovery requires an incomplete first install with no service definition.'
	recovery_protected_path "$(dirname "$STATE_DIR")"
	# Older download failures could leave ONLY the empty service-owned directory.
	# No application is admitted/executed without provenance in this branch.
	PARTIAL_INSTALL_KIND='empty-state-only'
	local -a partial_paths=("$STATE_DIR")
	if [[ -e "$INSTALL_ROOT" || -L "$INSTALL_ROOT" || -e "$CONFIG_FILE" || -L "$CONFIG_FILE" ]]; then
		PARTIAL_INSTALL_KIND='verified-app-config'
		[[ -d "$INSTALL_ROOT" && -f "$CONFIG_FILE" ]] || fail 'Unknown partial app/config layout; separate recovery review is required.'
		recovery_protected_path "$INSTALL_ROOT"
		recovery_protected_path "$CONFIG_FILE" 600
		recovery_protected_path "$INSTALL_ROOT/.verified-install" 644
		partial_paths+=("$INSTALL_ROOT" "$CONFIG_FILE")
	fi
	local expected_device entry
	expected_device="$(stat -c '%d' "$(dirname "$STATE_DIR")")"
	for entry in "${partial_paths[@]}"; do
		[[ "$(stat -c '%d' "$entry")" == "$expected_device" ]] || fail 'Quarantine requires same-filesystem renames; separate recovery review is required.'
	done
	# ANY state, including an identity, temporary identity, policy, receipt, lock
	# or hidden file is evidence requiring separate operator review. Never purge.
	[[ "$(stat -c '%a' "$STATE_DIR")" == 700 && -z "$(find "$STATE_DIR" -mindepth 1 -print -quit)" ]] || fail 'Agent state is not empty; identity/receipts/partial enrollment must be preserved for review.'
	if [[ "$PARTIAL_INSTALL_KIND" == verified-app-config ]]; then
		grep -Fx 'distribution=pluton-agent-standalone-v1' "$INSTALL_ROOT/.verified-install" >/dev/null || fail 'Recovery requires protected standalone provenance.'
		grep -Fx 'format=1' "$INSTALL_ROOT/.verified-install" >/dev/null || fail 'Unsupported partial installation provenance.'
		local partial_node
		partial_node="$(sed -n 's/^node=//p' "$INSTALL_ROOT/.verified-install")"
		[[ "$partial_node" == "$NODE_VERSION" || "$partial_node" == "$PREVIOUS_NODE_VERSION" ]] || fail 'Unsupported partial Node toolchain.'
		grep -Fx "restic=$RESTIC_VERSION:$RESTIC_LINUX_AMD64_SHA256" "$INSTALL_ROOT/.verified-install" >/dev/null || fail 'Unsupported partial Restic pin.'
		grep -Fx "rclone=$RCLONE_VERSION:$RCLONE_LINUX_AMD64_SHA256" "$INSTALL_ROOT/.verified-install" >/dev/null || fail 'Unsupported partial rclone pin.'
		[[ -z "$(find "$INSTALL_ROOT" -mindepth 1 -maxdepth 1 ! -name app ! -name bin ! -name runtime ! -name .verified-install -print -quit)" ]] || fail 'Unexpected install state or transaction evidence; recovery refused.'
		local digest
		digest="$(verified_tree_digest "$INSTALL_ROOT")" || fail 'Partial artifacts failed ownership or integrity checks.'
		grep -Fx "tree=$digest" "$INSTALL_ROOT/.verified-install" >/dev/null || fail 'Partial artifacts differ from recorded SHA-256 integrity.'
	fi
	if is_test_mode; then
		[[ ! -e "$PLUTON_AGENT_TEST_ROOT/service-active" ]] || fail 'An Agent process is active; recovery refused.'
	else
		[[ "$(stat -c '%U' "$STATE_DIR")" == "$AGENT_USER" ]] || fail 'Unexpected state owner.'
		local account_uid process_status process_uid
		account_uid="$(id -u "$AGENT_USER")" || fail 'Expected service account is unavailable.'
		for process_status in /proc/[0-9]*/status; do
			process_uid="$(awk '$1 == "Uid:" { print $2; exit }' "$process_status" 2>/dev/null)" || {
				[[ ! -e "$process_status" ]] || fail 'Could not establish service account process absence.'
				continue
			}
			[[ "$process_uid" != "$account_uid" ]] || fail 'Service account has a running process; recovery refused.'
		done
		local unit status
		for unit in /run/systemd/system/pluton-agent.service /usr/lib/systemd/system/pluton-agent.service /lib/systemd/system/pluton-agent.service; do
			[[ ! -e "$unit" && ! -L "$unit" ]] || fail 'Another Agent unit exists; recovery refused.'
		done
		# Query the real manager, including a loaded/transient unit. No stop/reload.
		status="$(systemctl show pluton-agent.service --property=LoadState,ActiveState,MainPID 2>/dev/null)" || {
			[[ $? == 4 ]] || fail 'Could not establish service absence.'
		}
		[[ "$(printf '%s\n' "$status" | sort)" == $'ActiveState=inactive\nLoadState=not-found\nMainPID=0' ]] || fail 'An Agent service is loaded or active; recovery refused.'
	fi
}

quarantine_partial_installation() {
	validate_partial_installation
	local parent="$(dirname "$STATE_DIR")" destination
	# Fixed protected parent; no caller-selected output or destructive deletion.
	recovery_protected_path "$parent"
	destination="$(mktemp -d "$parent/pluton-agent-partial.XXXXXXXX")"
	chmod 0700 "$destination"
	log "Quarantine created: $destination. Retain it if any move fails; nothing is deleted."
	if [[ "$PARTIAL_INSTALL_KIND" == verified-app-config ]]; then
		mv -- "$INSTALL_ROOT" "$destination/install"
		if ! is_test_mode; then sync -f "$destination"; fi
		mv -- "$CONFIG_FILE" "$destination/config.env"
		if ! is_test_mode; then sync -f "$destination"; fi
	fi
	mv -- "$STATE_DIR" "$destination/state"
	if ! is_test_mode; then sync -f "$destination"; fi
	log "Eligible partial installation ($PARTIAL_INSTALL_KIND) quarantined. No service, identity, source data or server enrollment was modified. Fresh-install guards remain active."
}
