#!/usr/bin/env bash
# Build the agent binaries for every supported platform into <out-dir>.
#
# usage: scripts/build-release.sh <version> [out-dir]
#
#   version  release tag, e.g. v0.1.0 (injected as main.version)
#   out-dir  default: dist
#
# Names match internal/release: t3-mesh-agent-<os>-<arch>.
# Set T3_MESH_TRUSTED_KEYS to a comma-separated list of minisign public keys to
# override the compiled-in trusted keys at link time.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <version> [out-dir]" >&2
  exit 2
fi
version=$1
out=${2:-dist}

if [[ ! $version =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid version: $version" >&2
  exit 2
fi

cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p "$out"

ldflags="-s -w -X main.version=${version}"
if [[ -n ${T3_MESH_TRUSTED_KEYS:-} ]]; then
  ldflags+=" -X github.com/zekihan/t3-mesh/internal/release.TrustedKeysOverride=${T3_MESH_TRUSTED_KEYS}"
fi

# A FAULT file at the repository root builds a deliberately broken test release
# (agent-crash or launcher-crash, see cmd/t3-mesh-agent). Never present otherwise.
if [[ -f FAULT ]]; then
  fault=$(tr -d '[:space:]' <FAULT)
  case $fault in
    agent-crash | launcher-crash) ;;
    *) echo "invalid FAULT: $fault" >&2; exit 2 ;;
  esac
  echo "WARNING: building a deliberately broken release (fault: $fault)" >&2
  ldflags+=" -X main.fault=${fault}"
fi

export CGO_ENABLED=0
for platform in linux-amd64 darwin-arm64; do
  goos=${platform%-*}
  goarch=${platform#*-}
  echo "building t3-mesh-agent-${platform}" >&2
  GOOS=$goos GOARCH=$goarch go build -trimpath -ldflags "$ldflags" \
    -o "${out}/t3-mesh-agent-${platform}" ./cmd/t3-mesh-agent
done
