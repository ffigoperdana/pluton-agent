#!/usr/bin/env bash
# Disposable adapter only. No service process/cgroup is started by this fixture.
set -Eeuo pipefail
[[ -f /opt/pluton-disposable-ubuntu-test && -f /tmp/pluton-runtime-fixture-enabled && $EUID == 0 ]] || exit 90
case "${1:-}" in
  show)
    printf '%s\n' 'LoadState=loaded' 'Type=simple' 'KillMode=control-group' \
      'User=pluton-agent' 'Group=pluton-agent' 'FragmentPath=/etc/systemd/system/pluton-agent.service' \
      'DropInPaths=' 'Environment=' 'ExecStartPre=' 'ExecStartPost=' 'ExecStop=' 'ExecStopPost=' \
      'RootDirectory=' 'RootImage=' 'NoNewPrivileges=yes' 'CapabilityBoundingSet=' \
      'EnvironmentFiles=/etc/pluton-agent.env (ignore_errors=no)' \
      'ExecStart={ path=/opt/pluton-agent/runtime/bin/node ; argv[]=/opt/pluton-agent/runtime/bin/node /opt/pluton-agent/app/dist/index.js run ; }' \
      'ControlGroup='
    if [[ -f /tmp/pluton-runtime-fixture-active ]]; then printf '%s\n' 'ActiveState=active' 'SubState=running' 'MainPID=4242'
    else printf '%s\n' 'ActiveState=inactive' 'SubState=dead' 'MainPID=0'; fi ;;
  start)
    if [[ -f /tmp/pluton-runtime-fixture-fail-start ]]; then rm /tmp/pluton-runtime-fixture-fail-start; exit 1; fi
    touch /tmp/pluton-runtime-fixture-active ;;
  stop) rm -f /tmp/pluton-runtime-fixture-active ;;
  *) exit 91 ;;
esac
