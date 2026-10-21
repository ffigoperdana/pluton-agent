#!/usr/bin/env bash
# Only copied into a disposable container. This is NOT a real systemd test.
set -euo pipefail
[[ -f /opt/pluton-disposable-ubuntu-test && ${PLUTON_DISPOSABLE_INSTALL_TEST:-} == 1 ]] || exit 90
case "${1:-}" in
  --version) printf 'systemd 249 (container test adapter)\n' ;;
  is-active) [[ -f /tmp/pluton-fixture-service-active ]] ;;
  daemon-reload|enable|disable) : ;;
  restart|start) touch /tmp/pluton-fixture-service-active ;;
  stop) rm -f /tmp/pluton-fixture-service-active ;;
  *) exit 91 ;;
esac
