#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly apps_file="${script_dir}/apps.json"
readonly callback_script="${script_dir}/manifest_callback.py"
readonly github_org="${GITHUB_APP_OWNER:-darimuri}"
readonly verify_repository="${GITHUB_APP_VERIFY_REPOSITORY:-k8s-test}"
readonly webhook_placeholder_url="${GITHUB_APP_WEBHOOK_PLACEHOLDER_URL:-https://github.com/darimuri/k8s-test}"
readonly credential_root="${GITHUB_APP_CREDENTIALS_DIR:-${XDG_CONFIG_HOME:-${HOME}/.config}/darimuri-agent-orchestration/github-apps}"
readonly registration_url="https://github.com/organizations/${github_org}/settings/apps/new"
readonly run_dir="$(mktemp -d "${TMPDIR:-/tmp}/darimuri-github-apps.XXXXXX")"

dry_run=false
verify_only=false
include_future_roles=false
callback_pid=''

cleanup() {
  if [[ -n "${callback_pid}" ]] && kill -0 "${callback_pid}" 2>/dev/null; then
    kill "${callback_pid}" 2>/dev/null || true
    wait "${callback_pid}" 2>/dev/null || true
  fi
  rm -rf "${run_dir}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

die() {
  printf 'create-apps: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"
}

selected_app_names() {
  if [[ "${include_future_roles}" == "true" ]]; then
    jq -r '.[].name' "${apps_file}"
  else
    jq -r '.[] | select(.bootstrap == true) | .name' "${apps_file}"
  fi
}

expected_app() {
  local slug="$1"
  jq -c --arg slug "${slug}" '.[] | select(.name == $slug)' "${apps_file}"
}

canonical_permissions() {
  jq -c '(. // {}) | if .metadata == "read" then del(.metadata) else . end | to_entries | sort_by(.key) | from_entries'
}

canonical_events() {
  jq -c '(. // []) | sort | unique'
}

open_browser() {
  local url="$1"
  if command -v open >/dev/null 2>&1; then
    open "${url}" || printf '브라우저에서 다음 URL을 직접 여세요:\n%s\n' "${url}"
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "${url}" || printf '브라우저에서 다음 URL을 직접 여세요:\n%s\n' "${url}"
  else
    printf '브라우저에서 다음 URL을 여세요:\n%s\n' "${url}"
  fi
}

choose_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

base64url() {
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}

create_app_jwt() {
  local slug="$1"
  local app_json="${credential_root}/${slug}/app.json"
  local private_key="${credential_root}/${slug}/private-key.pem"
  local client_id
  local now
  local header
  local payload
  local unsigned
  local signature

  [[ -r "${app_json}" ]] || {
    printf 'App metadata를 읽을 수 없습니다: %s\n' "${app_json}" >&2
    return 1
  }
  [[ -r "${private_key}" ]] || {
    printf 'App private key를 읽을 수 없습니다: %s\n' "${private_key}" >&2
    return 1
  }
  client_id="$(jq -r '.client_id // empty' "${app_json}")"
  [[ -n "${client_id}" ]] || {
    printf 'App client_id가 없습니다: %s\n' "${app_json}" >&2
    return 1
  }

  now="$(date +%s)"
  header="$(printf '%s' '{"alg":"RS256","typ":"JWT"}' | base64url)"
  payload="$(jq -cn \
    --arg iss "${client_id}" \
    --argjson iat "$((now - 60))" \
    --argjson exp "$((now + 540))" \
    '{iat: $iat, exp: $exp, iss: $iss}' \
    | base64url)"
  unsigned="${header}.${payload}"
  signature="$(printf '%s' "${unsigned}" \
    | openssl dgst -sha256 -sign "${private_key}" \
    | base64url)"
  printf '%s.%s' "${unsigned}" "${signature}"
}

github_app_api() {
  local jwt="$1"
  local endpoint="$2"

  printf 'header = "Authorization: Bearer %s"\n' "${jwt}" \
    | curl \
      --config - \
      --silent \
      --show-error \
      --fail-with-body \
      --header 'Accept: application/vnd.github+json' \
      --header 'X-GitHub-Api-Version: 2026-03-10' \
      "https://api.github.com${endpoint}"
}

get_app_registration() {
  local slug="$1"
  local jwt
  local error_file="${run_dir}/${slug}.app.err"

  jwt="$(create_app_jwt "${slug}")" || return 1
  if ! github_app_api "${jwt}" /app 2>"${error_file}"; then
    printf '저장된 private key로 %s App registration을 조회하지 못했습니다.\n' \
      "${slug}" >&2
    sed 's/^/  /' "${error_file}" >&2
    return 1
  fi
}

app_owner() {
  local slug="$1"
  local error_file="${run_dir}/${slug}.lookup.err"
  local response

  if response="$(gh api "apps/${slug}" 2>"${error_file}")"; then
    printf '%s' "${response}" | jq -r '.owner.login'
    return 0
  fi
  if grep -q 'HTTP 404' "${error_file}"; then
    return 1
  fi
  sed 's/^/  /' "${error_file}" >&2
  return 2
}

save_credentials() {
  local expected_slug="$1"
  local manifest_file="$2"
  local conversion_file="$3"
  local actual_slug
  local actual_owner
  local staging_dir
  local destination
  local recovery_file

  if ! jq -e '.id and .slug and .pem and .client_id' "${conversion_file}" >/dev/null; then
    recovery_file="${credential_root}/.${expected_slug}.conversion-recovery.$(date +%s).json"
    cp "${conversion_file}" "${recovery_file}"
    chmod 0600 "${recovery_file}"
    die "manifest conversion response is incomplete; protected recovery file: ${recovery_file}"
  fi
  actual_slug="$(jq -r '.slug' "${conversion_file}")"
  actual_owner="$(jq -r '.owner.login // empty' "${conversion_file}")"
  destination="${credential_root}/${actual_slug}"
  [[ ! -e "${destination}" ]] || die "credential directory already exists: ${destination}"

  staging_dir="${credential_root}/.${actual_slug}.tmp.$$"
  mkdir -m 0700 "${staging_dir}"
  jq -r '.pem' "${conversion_file}" >"${staging_dir}/private-key.pem"
  jq -r '.webhook_secret // empty' "${conversion_file}" >"${staging_dir}/webhook-secret"
  jq -r '.client_secret // empty' "${conversion_file}" >"${staging_dir}/client-secret"
  jq 'del(.pem, .webhook_secret, .client_secret)' "${conversion_file}" \
    >"${staging_dir}/app.json"
  cp "${manifest_file}" "${staging_dir}/manifest.json"
  chmod 0600 "${staging_dir}"/*
  mv "${staging_dir}" "${destination}"

  printf 'Credential 저장 완료: %s\n' "${destination}" >&2
  if [[ "${actual_slug}" != "${expected_slug}" ]]; then
    printf '주의: 예상 slug=%s, 실제 slug=%s. 문서 매핑을 갱신하세요.\n' \
      "${expected_slug}" "${actual_slug}" >&2
  fi
  if [[ "${actual_owner}" != "${github_org}" ]]; then
    printf '오류: App 등록 소유자가 %s이며 예상 Organization %s가 아닙니다.\n' \
      "${actual_owner:-<empty>}" "${github_org}" >&2
    printf 'Credential은 복구를 위해 저장했지만 설치를 진행하지 않습니다: %s\n' \
      "${destination}" >&2
    return 2
  fi
  printf '%s' "${actual_slug}"
}

verify_installation() {
  local slug="$1"
  local jwt
  local registration
  local registration_owner
  local registration_slug
  local policy
  local expected_permissions
  local actual_permissions
  local actual_events
  local expected_repository_selection
  local response
  local installation_id
  local installation_permissions
  local installation_suspended_at
  local repository_selection
  local repository_response
  local installed_slug
  local error_file="${run_dir}/${slug}.installation.err"

  registration="$(get_app_registration "${slug}")" || return 1
  policy="$(expected_app "${slug}")"
  [[ -n "${policy}" ]] || {
    printf 'apps.json에 %s 정책이 없습니다.\n' "${slug}" >&2
    return 1
  }
  registration_slug="$(printf '%s' "${registration}" | jq -r '.slug // empty')"
  registration_owner="$(printf '%s' "${registration}" | jq -r '.owner.login // empty')"
  [[ "${registration_slug}" == "${slug}" ]] || {
    printf 'App registration slug 불일치: expected=%s actual=%s\n' \
      "${slug}" "${registration_slug:-<empty>}" >&2
    return 1
  }
  printf 'Registration owner: %s\n' "${registration_owner:-<empty>}"
  [[ "${registration_owner}" == "${github_org}" ]] || {
    printf '%s App ownership을 %s Organization으로 transfer해야 합니다.\n' \
      "${slug}" "${github_org}" >&2
    return 1
  }

  expected_permissions="$(printf '%s' "${policy}" | jq '.default_permissions' | canonical_permissions)"
  actual_permissions="$(printf '%s' "${registration}" | jq '.permissions' | canonical_permissions)"
  if [[ "${actual_permissions}" != "${expected_permissions}" ]]; then
    printf '%s App permission이 apps.json과 다릅니다.\n' "${slug}" >&2
    printf '  expected: %s\n  actual:   %s\n' \
      "${expected_permissions}" "${actual_permissions}" >&2
    printf '  settings: https://github.com/organizations/%s/settings/apps/%s/permissions\n' \
      "${github_org}" "${slug}" >&2
    return 1
  fi

  actual_events="$(printf '%s' "${registration}" | jq '.events' | canonical_events)"
  printf 'Registration permissions: apps.json과 일치\n'
  printf 'Registration event selections (informational; webhook must remain inactive): %s\n' \
    "${actual_events}"

  jwt="$(create_app_jwt "${slug}")" || return 1
  if ! response="$(github_app_api "${jwt}" /app/installations 2>"${error_file}")"; then
    sed 's/^/  /' "${error_file}" >&2
    return 1
  fi

  installation_id="$(printf '%s' "${response}" \
    | jq -r --arg account "${github_org}" \
      '[.[] | select(.account.login == $account)] | first | .id // empty')"
  repository_selection="$(printf '%s' "${response}" \
    | jq -r --arg account "${github_org}" \
      '[.[] | select(.account.login == $account)] | first | .repository_selection // empty')"
  installation_permissions="$(printf '%s' "${response}" \
    | jq --arg account "${github_org}" \
      '[.[] | select(.account.login == $account)] | first | .permissions' \
    | canonical_permissions)"
  installation_suspended_at="$(printf '%s' "${response}" \
    | jq -r --arg account "${github_org}" \
      '[.[] | select(.account.login == $account)] | first | .suspended_at // empty')"
  [[ -n "${installation_id}" ]] || {
    printf '%s에 설치된 %s App을 찾지 못했습니다.\n' "${github_org}" "${slug}" >&2
    if [[ "$(printf '%s' "${response}" | jq 'length')" -eq 0 ]]; then
      printf '  이 App에는 installation이 없습니다.\n' >&2
    else
      printf '  발견된 다른 installation:\n' >&2
      printf '%s' "${response}" \
        | jq -r '.[] | "    - account=\(.account.login) type=\(.account.type) scope=\(.repository_selection)"' \
        >&2
    fi
    return 1
  }

  expected_repository_selection="$(printf '%s' "${policy}" | jq -r '.repository_selection // empty')"
  [[ "${repository_selection}" == "${expected_repository_selection}" ]] || {
    printf 'Repository scope 불일치: expected=%s actual=%s\n' \
      "${expected_repository_selection:-<empty>}" "${repository_selection:-<empty>}" >&2
    return 1
  }
  printf 'Repository scope: All repositories\n'

  if [[ "${installation_permissions}" != "${expected_permissions}" ]]; then
    printf '%s installation 승인 권한이 apps.json과 다릅니다.\n' "${slug}" >&2
    printf '  expected: %s\n  actual:   %s\n' \
      "${expected_permissions}" "${installation_permissions}" >&2
    printf '  GitHub Organization owner가 변경 권한을 승인해야 합니다:\n' >&2
    printf '  https://github.com/organizations/%s/settings/installations/%s\n' \
      "${github_org}" "${installation_id}" >&2
    return 1
  fi
  [[ -z "${installation_suspended_at}" ]] || {
    printf '%s installation이 suspended 상태입니다: %s\n' \
      "${slug}" "${installation_suspended_at}" >&2
    return 1
  }
  printf 'Installation permissions: apps.json과 일치\n'

  if ! repository_response="$(github_app_api \
    "${jwt}" "/repos/${github_org}/${verify_repository}/installation" \
    2>"${error_file}")"; then
    printf '%s installation이 %s/%s에 접근하지 못합니다.\n' \
      "${slug}" "${github_org}" "${verify_repository}" >&2
    sed 's/^/  /' "${error_file}" >&2
    return 1
  fi
  installed_slug="$(printf '%s' "${repository_response}" | jq -r '.app_slug // empty')"
  [[ "${installed_slug}" == "${slug}" ]] || {
    printf 'Repository installation actor 불일치: expected=%s actual=%s\n' \
      "${slug}" "${installed_slug:-<empty>}" >&2
    return 1
  }

  printf 'Installation 확인: %s (id=%s)\n' "${slug}" "${installation_id}"
  printf 'Repository 접근 확인: %s/%s\n' "${github_org}" "${verify_repository}"
}

offer_installation() {
  local slug="$1"
  local answer
  local install_url="https://github.com/apps/${slug}/installations/new"

  read -r -p "${slug} 설치 화면을 열까요? [Y/n] " answer </dev/tty
  answer="${answer:-y}"
  if [[ ! "${answer}" =~ ^[Yy]$ ]]; then
    printf '설치를 건너뜁니다. 나중에 여세요: %s\n' "${install_url}"
    return
  fi

  cat <<EOF

브라우저에서 할 일:
  1. Install 대상 account로 ${github_org}를 선택합니다.
  2. 'All repositories'를 선택합니다.
  3. Install을 누릅니다.

${github_org}가 보이지 않으면 Organization owner인 dormael 계정으로 브라우저 로그인을
전환하세요. agent-darimuri 개인 계정을 선택하면 ${github_org}/${verify_repository}에
접근할 수 없습니다.

설치 URL: ${install_url}

EOF
  while true; do
    open_browser "${install_url}"
    read -r -p '설치를 완료했으면 Enter를 누르세요. ' </dev/tty
    if verify_installation "${slug}"; then
      return
    fi

    printf 'Installation 검증에 실패했습니다. 다음 App으로 자동 진행하지 않습니다.\n' >&2
    read -r -p '설치 화면을 다시 열기(r), 명시적으로 건너뛰기(s), 전체 중단(q): ' answer </dev/tty
    case "${answer}" in
      [Rr]) ;;
      [Ss])
        printf '%s installation 검증을 건너뜁니다.\n' "${slug}"
        return
        ;;
      [Qq])
        printf '중단합니다.\n'
        exit 0
        ;;
      *) printf 'r, s, q 중 하나를 입력하세요.\n' >&2 ;;
    esac
  done
}

create_app() {
  local slug="$1"
  local app_dir="${run_dir}/${slug}"
  local manifest_file="${app_dir}/manifest.json"
  local state
  local port
  local code_file="${app_dir}/code"
  local ready_file="${app_dir}/ready"
  local conversion_file="${app_dir}/conversion.json"
  local start_url
  local actual_slug

  [[ ! -e "${credential_root}/${slug}" ]] \
    || die "credential directory already exists before App creation: ${credential_root}/${slug}"
  mkdir -m 0700 "${app_dir}"
  state="$(openssl rand -hex 32)"
  port="$(choose_port)"
  jq --arg name "${slug}" \
    --arg redirect "http://127.0.0.1:${port}/callback" \
    --arg hook_url "${webhook_placeholder_url}" \
    '.[] | select(.name == $name) | del(.bootstrap, .repository_selection) | . + {
      redirect_url: $redirect,
      hook_attributes: {url: $hook_url, active: false}
    }' \
    "${apps_file}" >"${manifest_file}"
  [[ -s "${manifest_file}" ]] || die "manifest not found for ${slug}"

  python3 "${callback_script}" \
    --port "${port}" \
    --manifest "${manifest_file}" \
    --state "${state}" \
    --code-file "${code_file}" \
    --ready-file "${ready_file}" \
    --registration-url "${registration_url}" &
  callback_pid=$!

  for _ in {1..50}; do
    [[ -s "${ready_file}" ]] && break
    kill -0 "${callback_pid}" 2>/dev/null || die "local callback server stopped unexpectedly"
    sleep 0.1
  done
  [[ -s "${ready_file}" ]] || die "local callback server did not become ready"

  start_url="http://127.0.0.1:${port}/start"
  cat <<EOF

${slug} 생성 단계:
  1. 브라우저가 Organization owner인 dormael 계정인지 확인합니다.
  2. 등록 소유자가 ${github_org} Organization인지 확인합니다.
  3. App 이름을 변경하지 않습니다.
  4. 표시된 permission과 event를 검토합니다.
  5. 'Create GitHub App'을 누릅니다.
  6. localhost 완료 페이지가 보이면 터미널로 돌아옵니다.

브라우저가 열리지 않으면 다음 URL을 직접 여세요:
${start_url}

EOF
  open_browser "${start_url}"
  if ! wait "${callback_pid}"; then
    callback_pid=''
    die "GitHub manifest callback failed for ${slug}"
  fi
  callback_pid=''
  [[ -s "${code_file}" ]] || die "GitHub did not return a manifest code for ${slug}"

  gh api --method POST "/app-manifests/$(<"${code_file}")/conversions" \
    >"${conversion_file}"
  actual_slug="$(save_credentials "${slug}" "${manifest_file}" "${conversion_file}")"
  offer_installation "${actual_slug}"
}

main() {
  local slug
  local answer
  local owner
  local lookup_status
  local verification_failed=false
  local credential_dir
  local credential_id
  local credential_slug
  local credential_owner
  local registration
  local registration_id
  local registration_slug

  while (( $# > 0 )); do
    case "$1" in
      --dry-run) dry_run=true ;;
      --verify-installations) verify_only=true ;;
      --include-future-roles) include_future_roles=true ;;
      *) die "usage: $0 [--dry-run|--verify-installations] [--include-future-roles]" ;;
    esac
    shift
  done
  [[ "${dry_run}" != "true" || "${verify_only}" != "true" ]] \
    || die '--dry-run and --verify-installations cannot be combined'
  [[ -r "${apps_file}" ]] || die "missing app list: ${apps_file}"
  jq empty "${apps_file}" || die "invalid JSON: ${apps_file}"
  jq -e 'length > 0 and all(.[]; (.bootstrap | type) == "boolean" and .repository_selection == "all")' \
    "${apps_file}" >/dev/null \
    || die 'each App must declare boolean bootstrap and repository_selection=all'

  if [[ "${dry_run}" == "true" ]]; then
    jq -r '.[] | "\(.name)\n  permissions: \(.default_permissions | to_entries | map("\(.key)=\(.value)") | join(", "))\n  events: \(.default_events | if length == 0 then "none" else join(", ") end)"' \
      < <(jq --argjson include_future "${include_future_roles}" \
        '[.[] | select($include_future or .bootstrap == true)]' "${apps_file}")
    return
  fi

  require_command gh
  require_command jq
  require_command openssl
  require_command python3
  require_command curl
  [[ "${verify_repository}" =~ ^[A-Za-z0-9._-]+$ ]] \
    || die "invalid repository name for verification: ${verify_repository}"
  [[ -n "${credential_root}" && "${credential_root}" != "/" && "${credential_root}" != "${HOME}" ]] \
    || die "unsafe credential root: ${credential_root}"
  mkdir -p "${credential_root}"
  chmod 0700 "${credential_root}"

  if [[ "${verify_only}" == "true" ]]; then
    while IFS= read -r slug; do
      if [[ ! -d "${credential_root}/${slug}" ]]; then
        printf '%s: 필수 credential이 없습니다.\n' "${slug}" >&2
        verification_failed=true
        continue
      fi
      printf '\n%s 검증:\n' "${slug}"
      if ! verify_installation "${slug}"; then
        verification_failed=true
      fi
    done < <(selected_app_names)
    [[ "${verification_failed}" == "false" ]] \
      || die 'one or more installation checks failed'
    return
  fi

  gh auth status --hostname github.com >/dev/null 2>&1 \
    || die 'GitHub CLI authentication is invalid; run: gh auth login --hostname github.com'
  [[ -r /dev/tty ]] || die 'interactive terminal is required'

  printf 'GitHub organization: %s\n' "${github_org}"
  printf 'Credential root: %s\n' "${credential_root}"
  if [[ "${include_future_roles}" == "true" ]]; then
    printf 'Bootstrap 및 future 역할 App을 순서대로 처리합니다.\n\n'
  else
    printf 'Bootstrap 역할인 Control, Developer, Reviewer를 처리합니다.\n'
    printf 'Future 역할은 --include-future-roles를 지정해야 포함됩니다.\n\n'
  fi

  while IFS= read -r slug; do
    credential_dir="${credential_root}/${slug}"
    if [[ -r "${credential_dir}/app.json" ]]; then
      credential_id="$(jq -r '.id // empty' "${credential_dir}/app.json")"
      credential_slug="$(jq -r '.slug // empty' "${credential_dir}/app.json")"
      credential_owner="$(jq -r '.owner.login // empty' "${credential_dir}/app.json")"
      [[ "${credential_slug}" == "${slug}" ]] \
        || die "credential slug mismatch: expected=${slug} actual=${credential_slug:-<empty>}"

      registration="$(get_app_registration "${slug}")" \
        || die "cannot verify live registration for ${slug}; generate a new private key or follow the recovery in github-apps/README.md"
      registration_id="$(printf '%s' "${registration}" | jq -r '.id // empty')"
      registration_slug="$(printf '%s' "${registration}" | jq -r '.slug // empty')"
      owner="$(printf '%s' "${registration}" | jq -r '.owner.login // empty')"
      [[ "${registration_id}" == "${credential_id}" ]] \
        || die "App ID mismatch for ${slug}: credential=${credential_id:-<empty>} live=${registration_id:-<empty>}"
      [[ "${registration_slug}" == "${slug}" ]] \
        || die "live registration slug mismatch: expected=${slug} actual=${registration_slug:-<empty>}"
      [[ "${owner}" == "${github_org}" ]] \
        || die "${slug} live owner is ${owner:-<empty>}, expected ${github_org}; transfer ownership and rerun"
      if [[ "${credential_owner}" != "${owner}" ]]; then
        printf '%s ownership transfer 확인: saved=%s live=%s\n' \
          "${slug}" "${credential_owner:-<empty>}" "${owner}"
      fi
      printf '%s App credential이 이미 존재합니다.\n' "${slug}"
      offer_installation "${slug}"
      continue
    fi

    lookup_status=0
    owner="$(app_owner "${slug}")" || lookup_status=$?
    if (( lookup_status == 0 )); then
      if [[ "${owner}" != "${github_org}" ]]; then
        die "${slug} is already owned by ${owner}, not ${github_org}"
      fi
      printf '%s App은 이미 존재합니다.\n' "${slug}"
      offer_installation "${slug}"
      continue
    elif (( lookup_status != 1 )); then
      die "could not check whether ${slug} exists"
    fi

    read -r -p "${slug} App을 생성할까요? [Y/s/q] " answer </dev/tty
    answer="${answer:-y}"
    case "${answer}" in
      [Yy]) create_app "${slug}" ;;
      [SsNn]) printf '%s 생성을 건너뜁니다.\n' "${slug}" ;;
      [Qq]) printf '중단합니다.\n'; return ;;
      *) die "unsupported answer: ${answer}" ;;
    esac
  done < <(selected_app_names)
}

if [[ "${CREATE_APPS_LIB_ONLY:-false}" != "true" ]]; then
  main "$@"
fi
