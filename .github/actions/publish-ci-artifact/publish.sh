#!/usr/bin/env bash
set -euo pipefail

: "${ARTIFACT_NAME:?ARTIFACT_NAME is required}"
: "${ARTIFACT_PATHS:?ARTIFACT_PATHS is required}"
: "${NO_FILES_BEHAVIOUR:?NO_FILES_BEHAVIOUR is required}"
: "${RETENTION_DAYS:?RETENTION_DAYS is required}"
: "${GHCR_TOKEN:?GHCR_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_REPOSITORY_OWNER:?GITHUB_REPOSITORY_OWNER is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${SOURCE_SHA:?SOURCE_SHA is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"

case "${NO_FILES_BEHAVIOUR}" in
  error|warn|ignore) ;;
  *)
    echo "::error::if-no-files-found must be error, warn, or ignore"
    exit 2
    ;;
esac

if ! [[ "${RETENTION_DAYS}" =~ ^[1-7]$ ]]; then
  echo "::error::retention-days must be an integer from 1 to 7"
  exit 2
fi

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "${value}"
}

utc_plus_days() {
  if date -u -d "+${RETENTION_DAYS} days" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null; then
    return
  fi
  date -u -v+"${RETENTION_DAYS}"d '+%Y-%m-%dT%H:%M:%SZ'
}

shopt -s globstar nullglob dotglob
declare -a matches=()
declare -a excludes=()
declare -A seen=()

while IFS= read -r raw_pattern || [[ -n "${raw_pattern}" ]]; do
  raw_pattern="${raw_pattern%$'\r'}"
  [[ -z "${raw_pattern}" ]] && continue

  if [[ "${raw_pattern}" == '!'* ]]; then
    excludes+=("${raw_pattern:1}")
    continue
  fi

  search_pattern="${raw_pattern}"
  if [[ "${search_pattern}" == */'**' ]]; then
    search_pattern="${search_pattern%/**}"
  fi

  while IFS= read -r match; do
    [[ -e "${match}" ]] || continue
    if [[ -z "${seen[${match}]+x}" ]]; then
      seen["${match}"]=1
      matches+=("${match}")
    fi
  done < <(compgen -G "${search_pattern}" || true)
done <<< "${ARTIFACT_PATHS}"

if (( ${#matches[@]} == 0 )); then
  echo "published=false" >> "${GITHUB_OUTPUT}"
  case "${NO_FILES_BEHAVIOUR}" in
    error)
      echo "::error::No files matched artifact ${ARTIFACT_NAME}"
      exit 1
      ;;
    warn)
      echo "::warning::No files matched artifact ${ARTIFACT_NAME}"
      ;;
    ignore)
      echo "::notice::No files matched artifact ${ARTIFACT_NAME}; publication skipped"
      ;;
  esac
  exit 0
fi

staging="$(mktemp -d "${RUNNER_TEMP%/}/ci-artifact.XXXXXX")"
registry_config="${staging}/registry.json"
logged_in=false
cleanup() {
  if [[ "${logged_in}" == true ]]; then
    oras logout ghcr.io --registry-config "${registry_config}" >/dev/null 2>&1 || true
  fi
  rm -rf -- "${staging}"
}
trap cleanup EXIT

name_slug="$(printf '%s' "${ARTIFACT_NAME}" \
  | tr '[:upper:]' '[:lower:]' \
  | sed -E 's/[^a-z0-9._-]+/-/g; s/^-+//; s/-+$//' \
  | cut -c1-48)"
[[ -n "${name_slug}" ]] || name_slug=artifact
name_hash="$(printf '%s' "${ARTIFACT_NAME}" | sha256_file /dev/stdin | cut -c1-8)"

archive_name="${name_slug}.tar.gz"
archive_path="${staging}/${archive_name}"
tar_args=(-czf "${archive_path}")
for exclude in "${excludes[@]}"; do
  tar_args+=("--exclude=${exclude}")
done
tar "${tar_args[@]}" -- "${matches[@]}"

archive_sha256="$(sha256_file "${archive_path}")"
archive_bytes="$(wc -c < "${archive_path}" | tr -d '[:space:]')"
created_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
expires_at="$(utc_plus_days)"
expiry_tag="$(printf '%s' "${expires_at}" | tr -d ':-' | cut -c1-8)"

repository_name="${GITHUB_REPOSITORY#*/}"
owner="$(printf '%s' "${GITHUB_REPOSITORY_OWNER}" | tr '[:upper:]' '[:lower:]')"
package="$(printf '%s-ci-artifacts' "${repository_name}" | tr '[:upper:]' '[:lower:]')"
tag="run-${GITHUB_RUN_ID}-a${GITHUB_RUN_ATTEMPT}-${name_slug}-${name_hash}-e${expiry_tag}"
reference="ghcr.io/${owner}/${package}:${tag}"

cat > "${staging}/manifest.json" <<EOF
{
  "schemaVersion": 1,
  "artifactName": "$(json_escape "${ARTIFACT_NAME}")",
  "archive": "$(json_escape "${archive_name}")",
  "archiveSha256": "${archive_sha256}",
  "archiveBytes": ${archive_bytes},
  "repository": "$(json_escape "${GITHUB_REPOSITORY}")",
  "commit": "${SOURCE_SHA}",
  "workflowSha": "${GITHUB_SHA}",
  "workflow": "$(json_escape "${GITHUB_WORKFLOW:-unknown}")",
  "job": "$(json_escape "${GITHUB_JOB:-unknown}")",
  "runId": "${GITHUB_RUN_ID}",
  "runAttempt": "${GITHUB_RUN_ATTEMPT}",
  "createdAt": "${created_at}",
  "expiresAt": "${expires_at}"
}
EOF

printf '%s' "${GHCR_TOKEN}" | oras login ghcr.io \
  --username "${GITHUB_ACTOR:-github-actions}" \
  --password-stdin \
  --registry-config "${registry_config}"
logged_in=true

digest="$(
  cd "${staging}"
  oras push "${reference}" \
    --registry-config "${registry_config}" \
    --artifact-type application/vnd.krotname.ci-artifact.v1 \
    --annotation "org.opencontainers.image.source=${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY}" \
    --annotation "org.opencontainers.image.revision=${SOURCE_SHA}" \
    --annotation "org.opencontainers.image.created=${created_at}" \
    --annotation "io.krotname.ci-artifact.expires-at=${expires_at}" \
    --format go-template \
    --template '{{.digest}}' \
    "${archive_name}:application/gzip" \
    "manifest.json:application/vnd.krotname.ci-artifact.metadata.v1+json"
)"

resolved="$(oras resolve "${reference}" --registry-config "${registry_config}")"
if [[ "${resolved}" != "${digest}" ]]; then
  echo "::error::GHCR digest readback ${resolved} does not match pushed digest ${digest}"
  exit 1
fi

{
  echo "published=true"
  echo "package=${package}"
  echo "reference=${reference}"
  echo "digest=${digest}"
  echo "sha256=${archive_sha256}"
  echo "expires-at=${expires_at}"
} >> "${GITHUB_OUTPUT}"

{
  echo "### Private GHCR artifact: ${ARTIFACT_NAME}"
  echo
  echo "- Reference: \`${reference}@${digest}\`"
  echo "- Payload SHA-256: \`${archive_sha256}\`"
  echo "- Expires: \`${expires_at}\`"
} >> "${GITHUB_STEP_SUMMARY}"
