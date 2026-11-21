# t3-mesh

A private mesh between machines running T3. A hub in the homelab
cluster relays mTLS tunnels between per-machine agents, with a direct path while the
machines share a LAN. Agents update themselves from signed GitHub releases. The
design, threat model and rollout are in [docs/design.md](docs/design.md).
The Android app that connects to the mesh with client certificates is planned in
[zekihan/t3code](https://github.com/zekihan/t3code/blob/main/docs/android-fork.md).

- `cmd/t3-mesh-hub`: the hub, shipped as a distroless container image.
- `cmd/t3-mesh-agent`: the agent (`launcher`, `run`, `enroll`, `fallback`, `version`),
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
kubectl -n t3-mesh exec deploy/t3-mesh-hub -- t3-mesh-hub enroll-token --device device-z-phone-mesh
```

The command refuses agent identities and every name not listed under `devices`, and an
agent token cannot enroll a device. The app speaks the enrollment protocol and renews
through `POST /api/v1/renew`; both are specified in
[docs/design.md](docs/design.md#device-enrollment). A device whose renewal reply was
lost holds a superseded leaf and re-enrolls with a new token.

## Hub image

`ghcr.io/zekihan/t3-mesh-hub` (also on Docker Hub): `edge` from `main`, `X.Y.Z` and
`latest` for releases. The image runs as uid 65532 with a read-only root
filesystem; mount an `emptyDir` on `/run/t3-mesh` (admin socket) and set
`fsGroup: 65532`. Ports: 8443 (agents), 8080 (viewers), 9090 (probes). The homelab pins
`edge@sha256:...`.

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

Agents trust the minisign public keys compiled into
`internal/release/keys.go` (current and next). Both secret keys are stored in the
secrets repo; homelab `terraform/git` publishes only the current one to the
`release` environment as `MINISIGN_SECRET_KEY`. To rotate, publish the next key
as `MINISIGN_SECRET_KEY_NEXT` so manifests are dual-signed, then follow the
rotation steps in `docs/design.md`.

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
