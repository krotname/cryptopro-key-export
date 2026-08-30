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
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"

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

canonical_path() {
  python3 - "$1" <<'PY'
import os
import sys

print(os.path.realpath(sys.argv[1]))
PY
}

cd -- "${GITHUB_WORKSPACE}"
workspace="$(pwd -P)"

match_list="$(mktemp "${RUNNER_TEMP%/}/ci-artifact-matches.XXXXXX")"
if ! python3 - "${workspace}" "${ARTIFACT_PATHS}" "${match_list}" <<'PY'
import os
import fnmatch
import pathlib
import re
import sys

workspace = pathlib.Path(sys.argv[1]).resolve()
output = pathlib.Path(sys.argv[3])
seen = set()
matches = []


def has_magic(pattern):
    return any(character in pattern for character in "*?[")


def normalize_pattern(raw_pattern):
    pattern = raw_pattern.rstrip("\r").strip().replace("\\", "/")
    while pattern.startswith("./"):
        pattern = pattern[2:]
    candidate = pathlib.PurePosixPath(pattern)
    if not pattern or candidate.is_absolute() or ".." in candidate.parts:
        raise SystemExit(
            f"Artifact pattern must stay relative to GITHUB_WORKSPACE: {raw_pattern}"
        )
    return pattern


positive_patterns = []
exclude_patterns = []
for raw_pattern in sys.argv[2].splitlines():
    trimmed = raw_pattern.rstrip("\r").strip()
    if not trimmed:
        continue
    if trimmed.startswith("!"):
        exclude_patterns.append(normalize_pattern(trimmed[1:]))
    else:
        positive_patterns.append(normalize_pattern(trimmed))


def normalize_caret_classes(pattern_part):
    """fnmatch uses ! for negation while Bash accepts both ! and ^."""
    return re.sub(r"\[\^([^\]]+)\]", r"[!\1]", pattern_part)


def matches_glob(relative_path, pattern):
    """Match Bash-style path globs without implicitly matching dotfiles."""
    path_parts = pathlib.PurePosixPath(relative_path).parts
    pattern_parts = pathlib.PurePosixPath(pattern).parts
    visited = set()

    def visit(path_index, pattern_index):
        state = (path_index, pattern_index)
        if state in visited:
            return False
        visited.add(state)

        if pattern_index == len(pattern_parts):
            return path_index == len(path_parts)

        pattern_part = pattern_parts[pattern_index]
        if pattern_part == "**":
            if visit(path_index, pattern_index + 1):
                return True
            return (
                path_index < len(path_parts)
                and not path_parts[path_index].startswith(".")
                and visit(path_index + 1, pattern_index)
            )

        if path_index == len(path_parts):
            return False
        path_part = path_parts[path_index]
        if path_part.startswith(".") and not pattern_part.startswith("."):
            return False
        return fnmatch.fnmatchcase(
            path_part, normalize_caret_classes(pattern_part)
        ) and visit(
            path_index + 1, pattern_index + 1
        )

    return visit(0, 0)


def archive_entries(candidate):
    """Expand selected directories while excluding implicit hidden descendants."""
    if candidate.is_file() or candidate.is_symlink():
        yield candidate
        return
    if not candidate.is_dir():
        return

    for root, directory_names, file_names in os.walk(candidate, followlinks=False):
        root_path = pathlib.Path(root)
        retained_directories = []
        for directory_name in directory_names:
            if directory_name.startswith("."):
                continue
            directory_path = root_path / directory_name
            if directory_path.is_symlink():
                yield directory_path
            else:
                retained_directories.append(directory_name)
        directory_names[:] = retained_directories
        for file_name in file_names:
            if not file_name.startswith("."):
                yield root_path / file_name

for normalized_pattern in positive_patterns:
    wildcard_pattern = has_magic(normalized_pattern)
    if wildcard_pattern:
        candidates = workspace.glob(normalize_caret_classes(normalized_pattern))
    else:
        candidates = [workspace / normalized_pattern]

    for candidate in candidates:
        if not candidate.exists():
            continue
        candidate_relative = candidate.relative_to(workspace).as_posix()
        if wildcard_pattern and not matches_glob(candidate_relative, normalized_pattern):
            continue

        for archive_entry in archive_entries(candidate):
            resolved = archive_entry.resolve()
            try:
                resolved.relative_to(workspace)
                relative = archive_entry.relative_to(workspace)
            except ValueError as error:
                raise SystemExit(
                    f"Artifact path escapes GITHUB_WORKSPACE: {archive_entry}"
                ) from error
            relative_text = relative.as_posix()
            excluded = any(
                matches_glob(relative_text, exclude_pattern)
                or (
                    not has_magic(exclude_pattern)
                    and relative_text.startswith(exclude_pattern.rstrip("/") + "/")
                )
                for exclude_pattern in exclude_patterns
            )
            if excluded:
                continue
            if relative_text not in seen:
                seen.add(relative_text)
                matches.append(relative_text)

with output.open("wb") as stream:
    for match in matches:
        stream.write(os.fsencode(match) + b"\0")
PY
then
  rm -f -- "${match_list}"
  echo "::error::Invalid or unsafe artifact path pattern"
  exit 2
fi

if [[ ! -s "${match_list}" ]]; then
  rm -f -- "${match_list}"
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
  rm -f -- "${match_list}"
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
tar -czf "${archive_path}" --null -T "${match_list}"

archive_sha256="$(sha256_file "${archive_path}")"
archive_bytes="$(wc -c < "${archive_path}" | tr -d '[:space:]')"
created_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
expires_at="$(utc_plus_days)"
expiry_tag="$(printf '%s' "${expires_at}" | tr -d ':-' | sed -E 's/Z$//')"

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
