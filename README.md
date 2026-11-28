# t3-mesh

A private mesh between machines running T3. A hub in the homelab
cluster relays mTLS tunnels between per-machine agents, with a direct path while the
machines share a LAN. Agents update themselves from signed GitHub releases. The
design, threat model and rollout are in [docs/design.md](docs/design.md).
The Android app that connects to the mesh with client certificates is planned in
[zekihan/t3code](https://github.com/zekihan/t3code/blob/main/docs/android-fork.md).

- `cmd/t3-mesh-hub`: the hub, shipped as a distroless container image.
- `cmd/t3-mesh-agent`: the agent (`launcher`, `run`, `enroll`, `fallback`, `status`, `doctor`, `version`),
  shipped as static binaries for linux/amd64 and darwin/arm64.

## Build and test

```sh
go vet ./...
golangci-lint run
./scripts/go_test.sh -race ./...     # includes the hub + agents integration test
T3_COMPAT_BINARY=$(command -v t3) go test -run '^TestT3Compat$' ./test/integration  # against a real T3
scripts/build-release.sh v0.1.0      # agent binaries into dist/
scripts/make-manifest.sh v0.1.0      # dist/manifest.json
docker build -t t3-mesh-hub .
```

## Install an agent

Download the binary and check it against the manifest (the agent verifies the
signature itself on every later update):

```sh
v=v0.1.0; os=linux-amd64   # or darwin-arm64
curl -fLO https://github.com/zekihan/t3-mesh/releases/download/$v/t3-mesh-agent-$os
curl -fLO https://github.com/zekihan/t3-mesh/releases/download/$v/manifest.json
curl -fLO https://github.com/zekihan/t3-mesh/releases/download/$v/manifest.json.minisig
minisign -Vm manifest.json -P <public key>        # optional but recommended
grep -o "\"name\":\"t3-mesh-agent-$os\",\"sha256\":\"[0-9a-f]*\"" manifest.json   # compare with:
sha256sum t3-mesh-agent-$os                       # macOS: shasum -a 256
chmod +x t3-mesh-agent-$os
```

Then, from a checkout of this repository:

```sh
# Linux (systemd): user t3mesh, state in /var/lib/t3-mesh, config /etc/t3-mesh/agent.yaml
sudo packaging/linux/install.sh --binary ./t3-mesh-agent-linux-amd64 --version $v --name agent-z-arch

# macOS (LaunchDaemons): user _t3mesh, state in /Library/Application Support/t3-mesh
sudo packaging/darwin/install.sh --binary ./t3-mesh-agent-darwin-arm64 --version $v --name agent-z-mac
```

Edit the generated config (`links`, `direct`; see the design for the fields). The
installer enables the service but starts it only once the machine is enrolled.

With `direct` enabled, the agent also listens for enrolled devices (the Android app) on
`direct.devices.port`, 27443 unless set, under the same home gate; set
`direct.devices.enabled: false` to switch it off. Both listeners bind only addresses
inside the hub's `homeCIDRs`, so let the LAN reach TCP 27400 and 27443 on the host
firewall (for example an nftables input rule on Linux, and the application firewall on
macOS). See [Direct device access](docs/design.md#direct-device-access).

## Link to SSH on a peer

Upgrade the hub and both agents before adding a TCP service. To let z-arch
reach SSH on z-mac, add to the hub config alongside the existing T3 service
and rules:

```yaml
machines:
  z-mac:
    identity: agent-z-mac
    services:
      ssh: {kind: tcp}
policy:
  entries:
    mesh-ssh-z-mac: {identities: [agent-z-arch]}
```

On z-mac, add the local sshd endpoint to the agent config:

```yaml
serve:
  ssh: 127.0.0.1:22
```

On z-arch, add the loopback link to its agent config:

```yaml
links:
  ssh.z-mac: 127.0.0.1:27322
```

Run `ssh -p 27322 127.0.0.1` on z-arch. The link goes direct on the LAN
when available and otherwise through the hub. Any local process can open the
link. sshd still authenticates the SSH user. TCP services have no viewer host.

The homelab chart needs TCP support before it can render this config. It
currently accepts only HTTP. The deployment change must render TCP service
config and agent rules while generating viewer resources only for HTTP.
See [Homelab changes](docs/design.md#homelab-changes).

## Check an agent locally

The installer makes `t3-mesh-agent` available at `/usr/local/bin/t3-mesh-agent`.

Run `t3-mesh-agent status` for the live tunnel, direct path, listeners,
certificate, update state and service checks, even while the hub is unreachable.
Use `--json` for JSON or `--socket` to select a different socket.

Run `t3-mesh-agent doctor` to check the config, socket, serve targets, ports,
certificate, installed versions and hub DNS. It exits nonzero if a check fails.
Use `--json` for JSON or `--config` to check a different config file. Checks
that require root are skipped when permissions are missing.

The installers grant the login user access through the service group
(`t3mesh` on Linux, `_t3mesh` on macOS). Log out and back in for the group
membership to take effect. On an existing install, rerun the updated installer
to provision the socket directory and grant access.

## Enroll an agent

1. On the cluster, get a single-use token (valid 15 minutes):

   ```sh
   kubectl -n t3-mesh exec deploy/t3-mesh-hub -- t3-mesh-hub enroll-token agent-<machine>
   ```

2. On the machine, as the service user (Linux; on macOS use `_t3mesh` and the
   `/Library/Application Support/t3-mesh` paths):

   ```sh
   sudo -u t3mesh /var/lib/t3-mesh/install/known-good/t3-mesh-agent \
     enroll --config /etc/t3-mesh/agent.yaml --token <token>
   sudo systemctl start t3-mesh-agent          # macOS: sudo launchctl bootstrap system /Library/LaunchDaemons/com.noqer.t3-mesh-agent.plist
   ```

## Enroll a device

The Android app enrolls an enrolled-device identity (`device-<name>-mesh`, listed under
`devices` in the hub config) with a key in its Keystore. Get a single-use token, valid
15 minutes, and type it into the app:

```sh
kubectl -n t3-mesh exec deploy/t3-mesh-hub -- t3-mesh-hub enroll-token --qr --device device-z-phone-mesh
```

Scan the QR code with the phone's camera and paste the token into the app. The
command also prints the plain token.

The command refuses agent identities and every name not listed under `devices`, and an
agent token cannot enroll a device. The app speaks the enrollment protocol and renews
through `POST /api/v1/renew`; both are specified in
[docs/design.md](docs/design.md#device-enrollment). A device that loses a renewal reply can retry with its previous leaf and a CSR
for the same new key within 10 minutes. If replay is unavailable, it re-enrolls
with a new token.

## Hub image

`ghcr.io/zekihan/t3-mesh-hub` (also on Docker Hub): `edge` from `main`, `X.Y.Z` and
`latest` for releases. The image runs as uid 65532 with a read-only root
filesystem; mount an `emptyDir` on `/run/t3-mesh` (admin socket) and set
`fsGroup: 65532`. Ports: 8443 (agents), 8080 (viewers), 9090 (ops: status,
alerts, probes and the internal `/metrics` endpoint). The homelab pins
`edge@sha256:...`.

Run `t3-mesh-hub status`, `tokens`, `tokens revoke <id-prefix>` or
`disconnect <machine>` inside the hub pod using the same `kubectl exec` command
as for enrollment. The token list shows outstanding tokens by ID prefix,
identity, kind and expiry. Disconnect closes the machine's current tunnels so
its agent can reconnect.

Set `serve --config-map t3-mesh-hub-config` to watch the hub config and
`clients-ca-bundle` in the pod's namespace. The optional `--trust-config-map`
flag overrides the trust ConfigMap name. Give the hub ServiceAccount
`get`, `list` and `watch` on core ConfigMaps restricted to those two names.
Keep the existing mounts for startup and fallback.

Set `--persist-last-seen` to keep last-seen times across hub restarts. Create
an empty `t3-mesh-hub-state` ConfigMap in the hub namespace and give the hub
ServiceAccount `get` and `update` on that name. The hub writes only
`data["lastSeen.json"]`. Viewer pages for offline machines refresh every
15 seconds.

## Release process

1. Bump `VERSION` (`0.2.0`, no `v`) and, if the on-disk state format changed in a
   way older releases cannot read, `MIN_STATE_VERSION` (`v0.1.0`). Merge to `main`.
2. Tag the merge commit and push the tag: `git tag v0.2.0 && git push origin v0.2.0`.
   The tag must equal `v` + `VERSION` and be an ancestor of `main`; limit who can
   push `v*` tags with a tag ruleset.
3. The `Publish` workflow runs the full tests (including the integration test),
   builds the agent binaries, writes and signs `manifest.json`, attaches binaries,
   `manifest.json` and `manifest.json.minisig` to a new GitHub release, and
   publishes the hub image. Roll the agents out by bumping `release.version` in the
   homelab chart.

To prove rollback on real machines, a release can be built deliberately broken:
commit a `FAULT` file containing `agent-crash` (the agent exits at start, so the
launcher rolls back) or `launcher-crash` (a promoted launcher exits, so the fallback
repoints and records the version), tag it, then remove the file and release a fixed
version. Mark such releases as pre-releases.

To force a certificate renewal on a machine, create `renew-now` in the agent's state
directory (owned by the service user) and restart the agent.

Reruns are safe: a published release is left alone if its manifest is identical.
`main` also publishes the `edge` hub image nightly and on manual dispatch.

## Signing key

Agents trust the minisign public keys compiled into `internal/release/keys.go`.
The active signing key is stored in the secrets repo, and homelab
`terraform/git` publishes it to the `release` environment as `MINISIGN_SECRET_KEY`.
To rotate, sign a transition release that trusts both keys with the current key.
After the hub confirms that every deployed agent is running the transition
release, switch `MINISIGN_SECRET_KEY` to the replacement and publish a release
that trusts only the replacement key.

The keys are passwordless (the secrets store encrypts them at rest); the
workflow also accepts `MINISIGN_PASSWORD` / `MINISIGN_PASSWORD_NEXT` for encrypted
keys. Registry publication uses the repository secrets `DOCKER_USERNAME` and
`DOCKER_PASSWORD`, also managed by homelab `terraform/git`.

`scripts/sign-manifest.sh` does the same locally with the same environment variables.

To canary an agent release, set `machines.<name>.release.version` in the hub
config, wait for probation, then update the fleet `release.version` and remove the
pin. A downgrade requires `rollbackAllowed: true` on that machine’s pin.

Validate a hub configuration offline with `t3-mesh-hub validate --config config.yaml`;
add `--trust ca.crt` to validate the clients CA bundle too.

## Service health

The hub's `/status` shows each machine's local service checks in `serviceHealth`.
The fleet API exposes the same information under `services`. A connected agent
can report an unreachable service, and service health is unknown while the
agent is offline or has yet to report.

If a loopback HTTP service port accepts TCP connections on a non-loopback interface
address, the agent reports the service, port and address and the hub raises
`/alerts/agent-<machine>-exposed`. Check the service's bind address and any other
listener on that port. TCP services are excluded; services with an unknown kind are
checked until the hub supplies their kind.
