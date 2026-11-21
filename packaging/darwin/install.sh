#!/usr/bin/env bash
# Install the t3-mesh agent as LaunchDaemons on macOS. Run as root.
#
# usage: install.sh --binary <path> --version <vX.Y.Z> [--name agent-<machine>] [--hub <host>]
#
# Creates the _t3mesh user and group, the directories, stages the binary as the
# first known-good release, writes the config if absent and loads the daemons.
# A fresh install loads only the fallback daemon until the agent is enrolled:
#   sudo -u _t3mesh "/Library/Application Support/t3-mesh/install/known-good/t3-mesh-agent" \
#     enroll --config "/Library/Application Support/t3-mesh/agent.yaml" --token <token>
#   sudo launchctl bootstrap system /Library/LaunchDaemons/com.noqer.t3-mesh-agent.plist
# Written for the macOS system bash (3.2).
set -euo pipefail

binary=
version=
name=
hub=mesh.noqer.com
while [[ $# -gt 0 ]]; do
  case $1 in
    --binary) binary=${2:?}; shift 2 ;;
    --version) version=${2:?}; shift 2 ;;
    --name) name=${2:?}; shift 2 ;;
    --hub) hub=${2:?}; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n $binary && -n $version ]] || { echo "usage: $0 --binary <path> --version <vX.Y.Z> [--name agent-<machine>] [--hub <host>]" >&2; exit 2; }
[[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "invalid version: $version" >&2; exit 2; }
[[ -x $binary ]] || { echo "not an executable file: $binary" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ $(uname -s) == Darwin ]] || { echo "this installer is for macOS" >&2; exit 1; }

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
base="/Library/Application Support/t3-mesh"
install_dir="$base/install"
logs=/Library/Logs/t3-mesh
daemons=/Library/LaunchDaemons
user=_t3mesh
main_label=com.noqer.t3-mesh-agent
fallback_label=com.noqer.t3-mesh-agent-fallback
runtime_label=com.noqer.t3-mesh-agent-runtime
name=${name:-agent-$(hostname -s | tr '[:upper:]' '[:lower:]')}

# Pick the lowest id in the system range (300-399) that is free as both a UID and a GID.
free_id() {
  local id used
  used=$( { dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID; } | awk '{print $2}')
  for id in $(seq 300 399); do
    if ! grep -qx "$id" <<<"$used"; then
      echo "$id"
      return 0
    fi
  done
  return 1
}

if ! dscl . -read "/Groups/$user" >/dev/null 2>&1; then
  id=$(free_id) || { echo "no free id below 400" >&2; exit 1; }
  dscl . -create "/Groups/$user"
  dscl . -create "/Groups/$user" PrimaryGroupID "$id"
  dscl . -create "/Groups/$user" RealName "t3-mesh agent"
  dscl . -create "/Groups/$user" Password '*'
  echo "created group $user ($id)"
fi
if ! dscl . -read "/Users/$user" >/dev/null 2>&1; then
  gid=$(dscl . -read "/Groups/$user" PrimaryGroupID | awk '{print $2}')
  uid=$gid
  # Prefer a UID equal to the GID; fall back to any free id if that UID is taken.
  if dscl . -list /Users UniqueID | awk '{print $2}' | grep -qx "$uid"; then
    uid=$(free_id) || { echo "no free id below 400" >&2; exit 1; }
  fi
  dscl . -create "/Users/$user"
  dscl . -create "/Users/$user" UniqueID "$uid"
  dscl . -create "/Users/$user" PrimaryGroupID "$gid"
  dscl . -create "/Users/$user" UserShell /usr/bin/false
  dscl . -create "/Users/$user" RealName "t3-mesh agent"
  dscl . -create "/Users/$user" NFSHomeDirectory /var/empty
  dscl . -create "/Users/$user" Password '*'
  dscl . -create "/Users/$user" IsHidden 1
  echo "created user $user ($uid)"
fi

if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
  if ! dseditgroup -o checkmember -m "$SUDO_USER" "$user" | grep -q '^yes'; then
    dseditgroup -o edit -a "$SUDO_USER" -t user "$user"
  fi
  echo "Log out and back in as $SUDO_USER for $user group access to the agent status socket."
fi

install -d -m 0750 -o "$user" -g "$user" /var/run/t3-mesh
install -d -m 0755 -o root -g wheel "$base"
install -d -m 0700 -o "$user" -g "$user" "$base/identity"
install -d -m 0750 -o "$user" -g "$user" "$base/state"
install -d -m 0755 -o "$user" -g "$user" "$install_dir"
install -d -m 0755 -o "$user" -g "$user" "$logs"

if [[ ! -e "$base/agent.yaml" ]]; then
  sed -e "s#@NAME@#$name#" -e "s#@HUB@#$hub#" "$here/agent.yaml.example" >"$base/agent.yaml"
  chown root:wheel "$base/agent.yaml"
  chmod 0644 "$base/agent.yaml"
  echo "wrote $base/agent.yaml (edit links/direct for this machine)"
fi

# Create versions/ explicitly: install -d sets the owner of the last component only,
# and the agent stages updates there.
install -d -m 0755 -o "$user" -g "$user" "$install_dir/versions"
install -d -m 0755 -o "$user" -g "$user" "$install_dir/versions/$version"
install -m 0755 -o "$user" -g "$user" "$binary" "$install_dir/versions/$version/t3-mesh-agent"
if [[ -e $install_dir/known-good ]]; then
  echo "existing install found: staged $version but left the links alone (the agent updates itself)"
else
  ln -sfn "versions/$version" "$install_dir/current"
  ln -sfn "versions/$version" "$install_dir/known-good"
  # previous-good equal to known-good makes the fallback a no-op until the first update.
  ln -sfn "versions/$version" "$install_dir/previous-good"
  chown -h "$user:$user" "$install_dir/current" "$install_dir/known-good" "$install_dir/previous-good"
fi

install -d -m 0755 /usr/local/bin
ln -sfn "$install_dir/current/t3-mesh-agent" /usr/local/bin/t3-mesh-agent

for label in "$main_label" "$fallback_label" "$runtime_label"; do
  install -m 0644 -o root -g wheel "$here/$label.plist" "$daemons/$label.plist"
  launchctl bootout "system/$label" >/dev/null 2>&1 || true
done
launchctl bootstrap system "$daemons/$runtime_label.plist"
launchctl bootstrap system "$daemons/$fallback_label.plist"
if [[ -n $(ls -A "$base/identity") ]]; then
  launchctl bootstrap system "$daemons/$main_label.plist"
  echo "installed t3-mesh-agent $version as $name and loaded both daemons"
else
  echo "installed t3-mesh-agent $version as $name; main daemon not loaded, no identity yet. Enroll, then: launchctl bootstrap system $daemons/$main_label.plist"
fi
