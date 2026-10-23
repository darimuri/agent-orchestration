#!/usr/bin/env bash
# Shared by the manual provisioner and the host-only job adapter. No credentials
# are accepted as arguments; authentication belongs to the trusted host Git setup.
clone_independent_repository() {
  local url="$1" ref="$2" destination="$3" sha="${4:-}"
  git clone --no-hardlinks --no-checkout --branch "${ref}" -- "${url}" "${destination}"
  if [[ -n "${sha}" ]]; then
    [[ "$(git -C "${destination}" rev-parse 'HEAD^{commit}')" == "${sha}" ]] || return 1
    git -C "${destination}" -c core.hooksPath=/dev/null checkout --detach "${sha}"
  else
    git -C "${destination}" -c core.hooksPath=/dev/null checkout --force
  fi
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -euo pipefail
  [[ "$#" == 4 ]] || exit 1
  clone_independent_repository "$@"
fi
