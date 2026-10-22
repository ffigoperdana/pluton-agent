#!/usr/bin/env bash
# Only copied into a disposable container. This is NOT a real systemd test.
set -euo pipefail
[[ -f /opt/pluton-disposable-ubuntu-test && ${PLUTON_DISPOSABLE_INSTALL_TEST:-} == 1 ]] || exit 90
case "${1:-}" in
  --version) /lib/systemd/systemd --version; printf 'Container test adapter: lifecycle is simulated\n' ;;
  is-active) [[ -f /tmp/pluton-fixture-service-active ]] ;;
  show)
    [[ ! -e /etc/systemd/system/pluton-agent.service && ! -e /tmp/pluton-fixture-service-active ]] || exit 91
    printf 'LoadState=not-found\nActiveState=inactive\nMainPID=0\n' ;;
  daemon-reload|enable|disable) : ;;
  restart|start) touch /tmp/pluton-fixture-service-active ;;
  stop) rm -f /tmp/pluton-fixture-service-active ;;
  *) exit 91 ;;
esac
