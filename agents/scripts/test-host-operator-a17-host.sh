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
# Planning needs only Node and never imports the installed executor. Host actions
# require the immutable private install and a completely cleared environment.
if [ "$1" = --plan ]; then
  exec /usr/bin/env -i LANG=C.UTF-8 TZ=UTC /usr/local/bin/node "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../tests/host-operator" && pwd)/a17-host-entry.mjs" --plan
fi
exec /usr/bin/env -i XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus LANG=C.UTF-8 TZ=UTC \
  /home/dormael/.local/share/host-operator-a17-disposable/runtime/node \
  /home/dormael/.local/share/host-operator-a17-disposable/install/agents/tests/host-operator/a17-host-entry.mjs "$1"
