#!/usr/bin/env bash
# Generate manifest.json (the format of internal/release.Manifest) from built
# agent binaries.
#
# usage: scripts/make-manifest.sh <version> [dir] [min-state-version-file]
#
#   version                 release tag, e.g. v0.1.0
#   dir                     directory holding t3-mesh-agent-<os>-<arch> (default: dist);
#                           manifest.json is written there
#   min-state-version-file  default: MIN_STATE_VERSION in the repo root
#
# The manifest is signed as the exact bytes written, so do not reformat it.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo "usage: $0 <version> [dir] [min-state-version-file]" >&2
  exit 2
fi
version=$1
dir=${2:-dist}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
min_file=${3:-${root}/MIN_STATE_VERSION}

semver='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'
if [[ ! $version =~ $semver ]]; then
  echo "invalid version: $version" >&2
  exit 2
fi
min_state=$(tr -d '[:space:]' <"$min_file")
if [[ ! $min_state =~ $semver ]]; then
  echo "invalid minStateVersion in $min_file: $min_state" >&2
  exit 2
fi

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

platforms=(linux-amd64 darwin-arm64)
out=${dir}/manifest.json
{
  printf '{"version":"%s","minStateVersion":"%s","assets":[' "$version" "$min_state"
  sep=
  for platform in "${platforms[@]}"; do
    name=t3-mesh-agent-${platform}
    if [[ ! -f ${dir}/${name} ]]; then
      echo "missing asset: ${dir}/${name}" >&2
      exit 1
    fi
    printf '%s{"platform":"%s","name":"%s","sha256":"%s"}' \
      "$sep" "$platform" "$name" "$(sha256 "${dir}/${name}")"
    sep=,
  done
  printf ']}\n'
} >"${out}.tmp"
mv "${out}.tmp" "$out"
echo "wrote $out" >&2
