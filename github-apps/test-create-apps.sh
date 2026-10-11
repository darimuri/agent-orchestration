#!/usr/bin/env bash
set -euo pipefail

readonly test_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly create_apps="${test_script_dir}/create-apps.sh"
readonly scratch_dir="$(mktemp -d "${TMPDIR:-/tmp}/test-create-apps.XXXXXX")"
trap 'rm -rf "${scratch_dir}"' EXIT

fail() {
  printf 'test-create-apps: %s\n' "$*" >&2
  exit 1
}

default_output="$("${create_apps}" --dry-run)"
[[ "$(printf '%s\n' "${default_output}" | grep -c '^darimuri-')" -eq 3 ]] \
  || fail 'default dry run must contain exactly the three bootstrap Apps'
printf '%s\n' "${default_output}" | grep -q '^darimuri-agent-developer-a$' \
  || fail 'default dry run omitted Developer'
printf '%s\n' "${default_output}" | grep -q '^darimuri-agent-reviewer-a$' \
  || fail 'default dry run omitted Reviewer'
printf '%s\n' "${default_output}" | grep -q '^darimuri-agent-control-a$' \
  || fail 'default dry run omitted Control'

future_output="$("${create_apps}" --dry-run --include-future-roles)"
[[ "$(printf '%s\n' "${future_output}" | grep -c '^darimuri-')" -eq 6 ]] \
  || fail '--include-future-roles must contain all six Apps'

run_mock_verification() (
  local scope="${1:-all}"
  local mutation="${2:-none}"
  local credentials="${scratch_dir}/credentials-${scope}-${mutation}"
  mkdir -p \
    "${credentials}/darimuri-agent-control-a" \
    "${credentials}/darimuri-agent-developer-a" \
    "${credentials}/darimuri-agent-reviewer-a"

  GITHUB_APP_CREDENTIALS_DIR="${credentials}" CREATE_APPS_LIB_ONLY=true source "${create_apps}"

  create_app_jwt() {
    printf '%s' "$1"
  }

  get_app_registration() {
    local slug="$1"
    local permissions
    local events='[]'
    permissions="$(expected_app "${slug}" | jq '.default_permissions + {metadata: "read"}')"
    case "${mutation}:${slug}" in
      developer-extra-permission:darimuri-agent-developer-a)
        permissions="$(printf '%s' "${permissions}" | jq '.checks = "write"')"
        ;;
      reviewer-elevated-contents:darimuri-agent-reviewer-a)
        permissions="$(printf '%s' "${permissions}" | jq '.contents = "write"')"
        ;;
      developer-extra-event:darimuri-agent-developer-a)
        events='["push"]'
        ;;
    esac
    jq -cn \
      --arg slug "${slug}" \
      --arg owner "${github_org}" \
      --argjson permissions "${permissions}" \
      --argjson events "${events}" \
      '{slug: $slug, owner: {login: $owner}, permissions: $permissions, events: $events}'
  }

  github_app_api() {
    local slug="$1"
    local endpoint="$2"
    local permissions
    case "${endpoint}" in
      /app/installations)
        permissions="$(expected_app "${slug}" | jq '.default_permissions + {metadata: "read"}')"
        if [[ "${mutation}:${slug}" == \
          'developer-stale-installation-permission:darimuri-agent-developer-a' ]]; then
          permissions="$(printf '%s' "${permissions}" | jq 'del(.issues)')"
        fi
        jq -cn \
          --arg account "${github_org}" \
          --arg scope "${scope}" \
          --argjson permissions "${permissions}" \
          '[{id: 42, account: {login: $account, type: "Organization"}, repository_selection: $scope, permissions: $permissions, suspended_at: null}]'
        ;;
      /repos/*/installation)
        jq -cn --arg slug "${slug}" '{app_slug: $slug}'
        ;;
      *)
        printf 'unexpected mock endpoint: %s\n' "${endpoint}" >&2
        return 1
        ;;
    esac
  }

  main --verify-installations
)

run_mock_verification

if run_mock_verification selected >/dev/null 2>&1; then
  fail 'selected repository installation must be rejected'
fi
if run_mock_verification all developer-extra-permission >/dev/null 2>&1; then
  fail 'Developer extra permission must be rejected'
fi
if run_mock_verification all reviewer-elevated-contents >/dev/null 2>&1; then
  fail 'Reviewer elevated contents permission must be rejected'
fi
run_mock_verification all developer-extra-event >/dev/null \
  || fail 'inactive webhook event selections must be informational'
if run_mock_verification all developer-stale-installation-permission >/dev/null 2>&1; then
  fail 'unapproved installation permission change must be rejected'
fi

missing_credentials="${scratch_dir}/missing-required"
mkdir -p "${missing_credentials}"
if GITHUB_APP_CREDENTIALS_DIR="${missing_credentials}" CREATE_APPS_LIB_ONLY=true \
  bash -c 'source "$1"; main --verify-installations' _ "${create_apps}" >/dev/null 2>&1; then
  fail 'missing required Developer credential must fail verification'
fi

printf 'GitHub App bootstrap tests passed.\n'
