#!/bin/bash
# Explicit disposable acceptance only; no environment flag enables a live unit.
set -euo pipefail
case "${1-}" in
  --plan|--validate|--run-disposable) ;;
  *) echo '{"status":"NO_ACTION","code":"a17_driver_arguments"}' >&2; exit 2 ;;
esac
if [ "$#" -ne 1 ]; then
  echo '{"status":"NO_ACTION","code":"a17_driver_arguments"}' >&2
  exit 2
fi
# Planning is literal reviewed data emitted by Bash builtins only. No runtime,
# PATH lookup, private install, source-location lookup or environment evaluation.
if [ "$1" = --plan ]; then
  printf '%s\n' '{"status":"NO_ACTION","plan":{"unit":"host-operator.service","command":"/usr/bin/systemd-run","argv":["--user","--unit=host-operator.service","--service-type=exec","--quiet","--property=Type=exec","--property=ExitType=main","--property=Delegate=yes","--property=DelegateSubgroup=supervisor","--property=RemainAfterExit=no","--property=Restart=no","--property=KillMode=control-group","--property=KillSignal=SIGTERM","--property=FinalKillSignal=SIGKILL","--property=SendSIGKILL=yes","--property=TimeoutStopSec=2s","--property=UMask=0077","--property=NoNewPrivileges=yes","--property=CapabilityBoundingSet=","--property=AmbientCapabilities=","--property=StandardOutput=null","--property=StandardError=null","--property=UnsetEnvironment=PATH HOME LOGNAME USER SHELL MANAGERPID NOTIFY_SOCKET WATCHDOG_PID WATCHDOG_USEC MEMORY_PRESSURE_WATCH MEMORY_PRESSURE_WRITE","--property=Environment=XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus LANG=C.UTF-8 TZ=UTC","--","/home/dormael/.local/share/host-operator-a17-disposable/runtime/node","/home/dormael/.local/share/host-operator-a17-disposable/install/agents/tests/host-operator/a17-host-entry.mjs","--service"],"environment":{"XDG_RUNTIME_DIR":"/run/user/1000","DBUS_SESSION_BUS_ADDRESS":"unix:path=/run/user/1000/bus","LANG":"C.UTF-8","TZ":"UTC"}},"cleanup":"OWNER_INSPECTION_REQUIRED","hostAcceptance":"NOT_READY"}'
  exit 0
fi
# Host actions retain only the exact immutable private runtime.
exec /usr/bin/env -i XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus LANG=C.UTF-8 TZ=UTC \
  /home/dormael/.local/share/host-operator-a17-disposable/runtime/node \
  /home/dormael/.local/share/host-operator-a17-disposable/install/agents/tests/host-operator/a17-host-entry.mjs "$1"
