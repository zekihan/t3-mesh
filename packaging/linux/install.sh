#!/usr/bin/env bash
# Install the t3-mesh agent as a systemd service. Run as root.
#
# usage: install.sh --binary <path> --version <vX.Y.Z> [--name agent-<machine>] [--hub <host>]
#
# Creates the t3mesh user and directories, stages the binary as the first
# known-good release, writes /etc/t3-mesh/agent.yaml if absent and starts the
# service. After this the agent updates itself. A fresh install is enabled but
# not started until it is enrolled:
#   sudo -u t3mesh /var/lib/t3-mesh/install/known-good/t3-mesh-agent \
#     enroll --config /etc/t3-mesh/agent.yaml --token <token>
#   sudo systemctl start t3-mesh-agent
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
command -v systemctl >/dev/null || { echo "systemd is required" >&2; exit 1; }

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
base=/var/lib/t3-mesh
install_dir=$base/install
name=${name:-agent-$(hostname -s | tr '[:upper:]' '[:lower:]')}

install -D -m 0644 "$here/sysusers.d/t3-mesh.conf" /etc/sysusers.d/t3-mesh.conf
install -D -m 0644 "$here/tmpfiles.d/t3-mesh.conf" /etc/tmpfiles.d/t3-mesh.conf
install -m 0644 "$here/t3-mesh-agent.service" /etc/systemd/system/t3-mesh-agent.service
install -m 0644 "$here/t3-mesh-agent-fallback.service" /etc/systemd/system/t3-mesh-agent-fallback.service
systemd-sysusers /etc/sysusers.d/t3-mesh.conf
systemd-tmpfiles --create /etc/tmpfiles.d/t3-mesh.conf

if [[ ! -e /etc/t3-mesh/agent.yaml ]]; then
  sed -e "s#@NAME@#$name#" -e "s#@HUB@#$hub#" "$here/agent.yaml.example" >/etc/t3-mesh/agent.yaml
  chmod 0644 /etc/t3-mesh/agent.yaml
  echo "wrote /etc/t3-mesh/agent.yaml (edit links/direct for this machine)"
fi

install -d -m 0755 -o t3mesh -g t3mesh "$install_dir/versions/$version"
install -m 0755 -o t3mesh -g t3mesh "$binary" "$install_dir/versions/$version/t3-mesh-agent"
if [[ -e $install_dir/known-good ]]; then
  echo "existing install found: staged $version but left the links alone (the agent updates itself)"
else
  ln -sfn "versions/$version" "$install_dir/current"
  ln -sfn "versions/$version" "$install_dir/known-good"
  chown -h t3mesh:t3mesh "$install_dir/current" "$install_dir/known-good"
fi

systemctl daemon-reload
systemctl enable t3-mesh-agent.service
if [[ -n $(ls -A "$base/identity") ]]; then
  systemctl restart t3-mesh-agent.service
  echo "installed t3-mesh-agent $version as $name and started it"
else
  echo "installed t3-mesh-agent $version as $name; not started, no identity yet. Enroll, then: systemctl start t3-mesh-agent"
fi
