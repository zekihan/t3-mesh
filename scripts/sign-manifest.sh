#!/usr/bin/env bash
# Sign manifest.json with one or two minisign keys and write
# manifest.json.minisig (the signatures concatenated, as internal/release expects).
#
# usage: scripts/sign-manifest.sh [manifest.json]   (default: dist/manifest.json)
#
# Keys come from the environment, never from arguments:
#   MINISIGN_SECRET_KEY            contents of the current secret key file (required)
#   MINISIGN_SECRET_KEY_NEXT       contents of the next secret key file (optional, rotation)
#   MINISIGN_PASSWORD[_NEXT]       passwords, if the keys are encrypted
#   MINISIGN_BIN                   minisign CLI (default: minisign). Use the Go one:
#                                  go install aead.dev/minisign/cmd/minisign@v0.3.0
set -euo pipefail

manifest=${1:-dist/manifest.json}
bin=${MINISIGN_BIN:-minisign}
: "${MINISIGN_SECRET_KEY:?MINISIGN_SECRET_KEY is not set}"
[[ -f $manifest ]] || { echo "no such file: $manifest" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
umask 077

sign() { # <name> <key> <password>
  local name=$1 key=$2 password=$3
  printf '%s\n' "$key" >"$work/$name.key"
  printf '%s\n' "$password" | "$bin" -S -s "$work/$name.key" -x "$work/$name.minisig" -m "$manifest" >/dev/null
  # Sanity check: derive the public key and verify what was just signed.
  "$bin" -R -f -s "$work/$name.key" -p "$work/$name.pub" >/dev/null 2>&1 </dev/null || true
  if [[ -f $work/$name.pub ]]; then
    "$bin" -V -q -p "$work/$name.pub" -x "$work/$name.minisig" -m "$manifest"
  fi
}

sign current "$MINISIGN_SECRET_KEY" "${MINISIGN_PASSWORD:-}"
cat "$work/current.minisig" >"${manifest}.minisig"
if [[ -n ${MINISIGN_SECRET_KEY_NEXT:-} ]]; then
  sign next "$MINISIGN_SECRET_KEY_NEXT" "${MINISIGN_PASSWORD_NEXT:-}"
  cat "$work/next.minisig" >>"${manifest}.minisig"
fi
echo "wrote ${manifest}.minisig ($(grep -c '^untrusted comment: ' "${manifest}.minisig") signature(s))" >&2
