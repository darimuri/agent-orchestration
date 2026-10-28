#!/usr/bin/env bash
# Disposable host acceptance fixture only; does not alter Compose or running agents.
set -euo pipefail
(( EUID == 0 )) || { printf '%s\n' 'requires root for disposable UID 10001 fixture ownership' >&2; exit 1; }
command -v docker >/dev/null
scratch="$(mktemp -d)"
trap 'rm -rf -- "${scratch}"' EXIT
image="${1:-local/buzz-agent-codex:0.163.0}"
for role in dispatcher developer reviewer; do
  install -d -m 0755 -o 10001 -g 10001 "${scratch}/${role}"
  policy=readonly=true
  [[ "${role}" != developer ]] || policy=readonly=false
  docker run --rm --network none --read-only --cap-drop ALL --user 10001:10001 \
    --mount "type=bind,src=${scratch}/${role},dst=/workspace,${policy}" \
    --entrypoint node "${image}" -e '
      const fs = require("node:fs"), writable = process.argv[1] === "developer";
      try { fs.writeFileSync("/workspace/probe", "fixture"); if (!writable) process.exit(1); }
      catch (e) { if (writable || !["EROFS", "EACCES"].includes(e.code)) process.exit(1); }
    ' "${role}"
done
printf '%s\n' 'Disposable role mount writes passed'
# Explicit fourth conversation role has the same read-only workspace guarantee.
install -d -m 0755 -o 10001 -g 10001 "$scratch/host-operator"
docker run --rm --network none --read-only --cap-drop ALL --user 10001:10001 \
  --mount "type=bind,src=$scratch/host-operator,dst=/workspace,readonly" \
  --entrypoint node "$image" -e 'try{require("node:fs").writeFileSync("/workspace/probe","fixture");process.exit(1);}catch(e){if(!["EROFS","EACCES"].includes(e.code))throw e;}'
