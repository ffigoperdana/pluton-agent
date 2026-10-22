#!/usr/bin/env bash
# GET-only acquisition for pinned public dependencies. Never accepts an Agent
# endpoint, arbitrary URL, headers, body or enrollment credential.

download_dependency() {
	local dependency="$1" destination="$2" url label
	case "$dependency" in
		node) label=Node; url="$NODE_DIST_BASE/$NODE_VERSION/node-${NODE_VERSION}-linux-x64.tar.xz" ;;
		node-checksums) label=Node-checksums; url="$NODE_DIST_BASE/$NODE_VERSION/SHASUMS256.txt" ;;
		restic) label=Restic; url="$RESTIC_RELEASE_BASE/restic_${RESTIC_VERSION}_linux_amd64.bz2" ;;
		rclone) label=Rclone; url="$RCLONE_RELEASE_BASE/rclone-v${RCLONE_VERSION}-linux-amd64.zip" ;;
		*) log 'Dependency GET refused: unsupported artifact.'; return 1 ;;
	esac
	[[ ! -e "$destination" && ! -L "$destination" && ! -e "$destination.part" && ! -L "$destination.part" ]] || {
		log "Dependency $label refused: destination already exists."; return 1;
	}
	local attempt started=$SECONDS remaining maximum status code retry reason delay
	for attempt in 1 2 3 4; do
		remaining=$((300 - (SECONDS - started)))
		(( remaining > 0 )) || break
		maximum=120; (( remaining >= maximum )) || maximum=$remaining
		# --disable MUST be first: a user curlrc must not inject auth, uploads,
		# insecure TLS or its own unbounded retries. Redirects remain HTTPS-only.
		code=0
		status="$(curl --disable --silent --fail --location --max-redirs 5 \
			--proto '=https' --proto-redir '=https' --tlsv1.2 --request GET \
			--retry 0 --connect-timeout 30 --max-time "$maximum" \
			--output "$destination.part" --write-out '%{http_code}' "$url" 2>/dev/null)" || code=$?
		if [[ "$code" == 0 && "$status" == 200 ]]; then
			mv -- "$destination.part" "$destination" || return 1
			return 0 # Caller MUST verify SHA-256 before extraction/execution.
		fi
		rm -f -- "$destination.part" || return 1
		retry=false; reason='download rejected'
		case "$code" in
			5|6) retry=true; reason='DNS resolution failed' ;;
			7|18|52|55|56|92) retry=true; reason='temporary network interruption' ;;
			28) retry=true; reason='download timed out' ;;
			22)
				case "$status" in
					408|429|500|502|503|504) retry=true; reason="temporary HTTP $status" ;;
					[0-9][0-9][0-9]) reason="HTTP $status rejected" ;;
				esac ;;
			51|58|60|77|83|90|91) reason='TLS verification or configuration failed' ;;
		esac
		log "Dependency $label GET attempt $attempt/4: $reason."
		[[ "$retry" == true && "$attempt" -lt 4 ]] || return 1
		delay=$((2 ** attempt)) # 2, 4, 8 seconds; never a request replay outside this helper.
		remaining=$((300 - (SECONDS - started)))
		(( remaining > delay )) || break
		log "Dependency $label: retrying GET in ${delay}s (300s total budget)."
		sleep "$delay" || return 1
	done
	log "Dependency $label: GET retry/time budget exhausted."
	return 1
}
