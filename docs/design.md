# t3-mesh design

Status: accepted design, not implemented. Date: 2026-11-16.

t3-mesh connects the T3 Code machines (devbox, z-arch, z-mac) to each other and to
the phone and tablet, with client certificates as the only way in. It does not use
a VPN, Tailscale or T3 Connect. It is a hub in cluster-1 plus one agent per machine.
Agents dial out to the hub and keep one tunnel open, so a machine is reachable from
any network it is on, while machines at home talk to each other directly.

## Goals

- Every machine's T3 server listens on `127.0.0.1` only. The network reaches it
  only through mTLS.
- Phone and tablet reach any machine from the internet with their existing client
  identities, in a browser.
- `t3 environment link` works between any two machines, home or away, although T3
  cannot present a client certificate.
- Machines at home talk to each other directly, without the cluster, and keep
  doing so through a cluster outage.
- z-mac stays reachable when it leaves home.
- Agents renew their own certificates and update themselves without manual steps.

## Non-goals

- A general VPN or layer-3 network. The mesh carries named TCP streams only.
- Replacing T3's own pairing. It stays on as a second lock.
- Raw TCP services for viewers (e.g. SSH to z-mac) in v1. See
  [Open items](#open-items).
- Machine-to-machine traffic between two machines that are both away.
  It goes through the hub, which is correct but not optimised.

## Background

- The current `devbox.noqer.com` route (homelab `apps/devbox`) sends Traefik mTLS
  traffic to `192.168.2.71:3773` over the LAN. It covers devbox only, needs a LAN
  address per machine, and cannot reach a machine that is away.
- `t3 environment link <url> --url <alt> --url <alt>` stores an ordered list of
  addresses, but the T3 server has no setting for a client certificate on outbound
  connections. It only reads `NODE_EXTRA_CA_CERTS` for server trust.
- Client identities come from the homelab `clients/v1` CA (`platform/mtls-pki`):
  ECDSA P-256, 1 year, renewed 30 days early, one URI SAN
  `urn:noqer:mtls:clients:<name>`. Per-host authorization lives in
  `libs/mtls-policy`.
- Public traffic reaches Traefik through OCI frps and the in-cluster frpc on the
  `websecure-frp` entrypoint, with PROXY v2 carrying the real client address.
  LAN traffic reaches the Traefik VIP `192.168.2.81` directly, with
  `externalTrafficPolicy: Local` preserving the LAN source address. Technitium
  answers each published `noqer.com` host with the LAN address at home; the new
  names need their own Technitium records too.
- Reusable code: `zekihan/release-workflows` (publishing), `zekihan/go-commons`.
  `zekihan/mtls-proxy` solves the same "add a client certificate" problem for one
  upstream and is a reference, not a dependency.

## Architecture

```
                         ┌──────────────── cluster-1 ────────────────┐
 phone / tablet          │                                           │
  t3.devbox.mesh.noqer.com ──mTLS──> Traefik (HTTP, policy) ──> hub  │
                         │                                     ║ ║ ║ │
  agents                 │  mesh.noqer.com ──> Traefik (TCP passthrough,
                         │                      PROXY v2) ──> hub    │
                         └─────────────────────────────────────╫─╫─╫─┘
                                       tunnels (agent dials)    ║ ║ ║
                  ┌─────────────────────────────────────────────╝ ║ ╚──────────────────┐
           agent on devbox                                agent on z-arch       agent on z-mac
           127.0.0.1:3773                                 127.0.0.1:3773        127.0.0.1:3773
                  ╰────────── direct mTLS, LAN, while both home ──────╯
```

Paths:

| From | To | Path |
|---|---|---|
| Phone, home or away | any machine | Traefik (viewer mTLS + policy) → hub → that machine's tunnel → `127.0.0.1:3773` |
| Machine A | machine B, both home | A's link port → direct mTLS to B's direct listener → `127.0.0.1:3773` |
| Machine A | machine B, otherwise | A's link port → A's tunnel → hub → B's tunnel → `127.0.0.1:3773` |

A tunnel's route is decided by DNS when the agent dials: at home, Technitium
answers `mesh.noqer.com` with the Traefik VIP and the tunnel is LAN-only; away,
public DNS answers with the OCI gateways. A phone at home likewise reaches the hub
over the LAN. The only path that crosses OCI twice is a viewer reaching z-mac while
z-mac is away, which no design can avoid.

## Naming

- Agent endpoint: `mesh.noqer.com`.
- Viewer hosts: `<svc>.<machine>.mesh.noqer.com`, e.g. `t3.devbox.mesh.noqer.com`,
  `t3.z-arch.mesh.noqer.com`, `t3.z-mac.mesh.noqer.com`.
- Each name has its own DNS record (DNS-only CNAME to the FRP gateway, like the
  current devbox host) and its own certificate. No wildcard records or certificates.
- Agent identities: `agent-<machine>`, URI SAN `urn:noqer:mtls:clients:agent-<machine>`.
- Policy entries in `libs/mtls-policy`: `mesh-<svc>-<machine>`, e.g. `mesh-t3-devbox`.

## Identities and PKI

### Agent identities

`libs/mtls-policy` gains a kind `agent` with `agent-devbox`, `agent-z-arch` and
`agent-z-mac`. They are separate from the device identities (`z-arch`, `z-mac`)
so revoking a machine's tunnel does not touch its browser certificate, and a
browser certificate can never register as a machine.

Agent certificates carry `clientAuth` and `serverAuth`, because the direct listener
is a TLS server. Device certificates are unchanged. Agent certificates have no
`Certificate` resource and no cluster Secret: the key exists only on the machine.
Homelab tests that assume every identity has a Certificate exclude kind `agent`.

### approver-policy

cert-manager currently auto-approves every CertificateRequest. A hub allowed to
create requests on the clients Issuer could otherwise mint any identity, including
phone certificates. Therefore:

1. Install cert-manager approver-policy and disable the built-in approver
   (`--controllers=*,-certificaterequests-approver`).
2. One `CertificateRequestPolicy` per existing issuer that allows the cert-manager
   controller exactly what it does today. A homelab chart test fails when an issuer
   has no policy.
3. One policy for the hub's ServiceAccount, on the clients Issuer only:
   - URI SAN exactly matching `urn:noqer:mtls:clients:agent-*`, no other SANs,
     no common name;
   - usages `client auth`, `server auth`, `digital signature`;
   - duration 8760h; ECDSA P-256 keys;
   - bound to the requester with RBAC `use`, so no other account can use it.

The hub adds its own checks on top: the requested name must equal the requesting
agent's own identity (or the enrollment token's identity), the identity must be
listed and not disabled, and the CSR key must differ from the current one.

### Enrollment

1. The operator runs `kubectl -n t3-mesh exec deploy/t3-mesh-hub -- t3-mesh-hub
   enroll-token agent-z-mac`. This CLI mode does not hold tokens itself: it asks the
   running hub over an admin unix socket inside the pod (`/run/t3-mesh/admin.sock`,
   mode `0600`, not exposed on any port). The hub prints a single-use token bound to
   that identity, valid for 15 minutes, held hashed in the server's memory. A hub
   restart invalidates outstanding tokens.
2. On the machine: `t3-mesh-agent enroll --token <token>`. The agent generates an
   ECDSA P-256 key locally in a `0600` file, connects to
   `mesh.noqer.com` without a client certificate and sends the CSR with the token.
3. The hub creates the CertificateRequest, waits for it to be issued, and returns
   the certificate and the CA chain. The agent stores them and reconnects with the
   new identity.

Only the `Enroll` call is accepted on a connection without a client certificate;
any other message or data stream on such a connection closes it. Enrollment is
rate-limited per source address, and every attempt is logged.

Enrollment is also the recovery path for an agent whose certificate expired, for
example after more than 30 days offline: the hub refuses the expired certificate, so
the operator issues a new token.

### Renewal

When less than 30 days remain (matching `renewBefore: 720h`), the agent generates a
new key and sends a CSR over its tunnel. It keeps the old key and certificate until
a new tunnel handshake with the new certificate succeeds, then deletes the old key.
Peers need no update, because direct connections do not pin leaf fingerprints. A
renewal that fails is retried hourly. An alert fires at 14 days left.

The agent does not renew while a new version is on probation (see
[Self-update](#self-update)), so a rollback never meets an identity written by a
version that did not survive.

### Revocation

Disabled identities and blocked leaf fingerprints from `libs/mtls-policy` apply
everywhere:

- The hub refuses a revoked agent on connect and closes its existing tunnel when
  the policy changes.
- The hub pushes the revocation list to agents with the rules. Agents refuse a
  revoked peer on direct connections.
- Checks apply to live sessions, not only new ones. The hub tracks every relayed and
  viewer stream by source identity; agents track every direct session by peer
  identity and certificate. When a revocation, a rule removal, the peer
  certificate's expiry or the end of the cache window makes a session no longer
  allowed, the hub or agent closes it at once. A long-lived T3 WebSocket therefore
  cannot outlive the permission that opened it.
- Removing an agent from the policy is the routine way to retire a machine.

## Hub

One Deployment in namespace `t3-mesh`, owned image pinned as `edge@sha256:`.

### Listeners

| Port | Reached through | Purpose |
|---|---|---|
| 8443 | Traefik `IngressRouteTCP`, `HostSNI(mesh.noqer.com)`, TLS passthrough, PROXY v2 | Agent tunnels and enrollment. The hub terminates TLS with its Let's Encrypt certificate and verifies agent certificates against the clients CA. |
| 8080 | Traefik `IngressRoute` per viewer host, with the `mesh-<svc>-<machine>` policy middleware | Viewer HTTP and WebSocket traffic. |
| 9090 | in-cluster scrape | `/metrics`, `/healthz`, `/readyz` |

NetworkPolicy admits only Traefik on 8443 and 8080: the hub trusts the PROXY v2
source on 8443 (home detection, rate limits) and the viewer header on 8080, so
nothing else may reach them.

The hub's `mesh.noqer.com` certificate is a cert-manager Let's Encrypt certificate
like every other host. Agents verify it with system roots and the exact hostname.
The hub reloads the mounted certificate and clients CA bundle when the files change,
so renewals need no restart.

### Configuration

Rendered by the chart from its values plus `libs/mtls-policy`:

```yaml
machines:
  devbox:
    identity: agent-devbox
    services:
      t3: {kind: http}
  z-arch:
    identity: agent-z-arch
    services:
      t3: {kind: http}
  z-mac:
    identity: agent-z-mac
    services:
      t3: {kind: http}
homeCIDRs: [192.168.0.0/22]
release:
  version: v0.3.0      # what agents should run; bumped by Renovate
```

Machine-to-machine rules come from the same `mesh-<svc>-<machine>` policy entries as
viewer rules: `agent-z-arch` in the `mesh-t3-devbox` identities list means z-arch's
agent may reach t3 on devbox. One list covers people and machines.

The list of machines and services is fixed. An agent announces what it serves; the
hub accepts only listed services and reports any difference as a metric and a log
event. The same list generates DNS records, certificates and Traefik routes.

The hub watches its mounted ConfigMap and applies changes live (rules, revocations,
desired version). The pod template carries no ConfigMap checksum, so a release bump
does not restart the hub or drop tunnels.

Traefik middlewares are rendered from the same policy entries with kind `agent`
filtered out, so an agent certificate is never accepted on a viewer host. Agent
identities in an entry only grant machine-to-machine access.

### Routing

- **Viewer request:** Traefik's middleware chain sets `X-T3-Mesh-Viewer` to the
  verified client identity, overwriting any value the client sent; the hub reads it
  and removes it before forwarding. The hub maps `Host` to `(machine, svc)`, opens a
  stream on that machine's newest tunnel session, and reverse-proxies the request over it,
  preserving `Host`, `Origin`, headers, paths, methods and WebSocket upgrades. No
  tunnel means `502` with a short page that names the machine and its last-seen time
  (since the last hub restart; the hub keeps no persistent state).
- **Agent-to-agent stream:** the hub checks the rule for the source agent, opens a
  stream on the target's tunnel and splices bytes. The hub does not parse the
  contents.

### Home detection

Traefik sends PROXY v2 to the hub's 8443 listener. For LAN clients the source is
the machine's LAN address (Traefik keeps it through `externalTrafficPolicy: Local`).
For clients through frps/frpc it is the public address carried by frpc's PROXY v2.
The hub marks an agent home when its tunnel source is inside `homeCIDRs` and tells
the agent in `HelloAck`. A café network that also uses `192.168.x` cannot fake
this, because its traffic arrives through frpc with a public source.

This holds only if the client cannot forge the PROXY header Traefik receives. The
`websecure-frp` entrypoint accepts PROXY headers only from frpc's source addresses
(`proxyProtocol.trustedIPs`, never `insecure`), and the LAN entrypoint accepts none.
M1 is not done until a forged PROXY header sent through the public path is
rejected or ignored.

### Availability

One replica with `Recreate` rollout. A deploy or node drain drops tunnels for a few
seconds; agents reconnect with backoff, and home machines keep talking directly.
The hub is single-replica by design. Running two replicas would need shared session
ownership, ordering and distribution of rules and revocations, and is future work
with its own design.

### Kubernetes permissions

- `create`, `get`, `watch` CertificateRequests in `mtls-pki`, bound to the approver
  policy above.
- Read its own ConfigMap. Nothing else.

## Agent

One static Go binary: `linux/amd64` (devbox, z-arch) and `darwin/arm64` (z-mac).
It runs as a system service under a dedicated user: a systemd unit with user
`t3mesh` on Linux, a LaunchDaemon with user `_t3mesh` on macOS. Neither runs in the
login session, so other processes of the logged-in user cannot read the key.

### Configuration

```yaml
identity:
  name: agent-z-arch
  dir: /var/lib/t3-mesh/identity  # macOS: /Library/Application Support/t3-mesh/identity

hub: mesh.noqer.com

serve:
  t3: 127.0.0.1:3773

links:                           # loopback ports for `t3 environment link`
  t3.devbox: 127.0.0.1:47301
  t3.z-mac:  127.0.0.1:47302

direct:
  enabled: true                  # hub bypass while home
  listen: :47400                 # served only while the hub says home
  cacheTTL: 168h                 # how long cached rules allow direct traffic
```

Link ports are explicit because T3 stores the URL; a port must never move. On each
machine, peers are linked with `t3 environment link http://127.0.0.1:<port>`.

Link ports are unauthenticated loopback listeners, so any local process on the
machine can use them; that is accepted on single-user machines. To block DNS
rebinding from browsers, a link port rejects HTTP requests whose `Host` is not
`127.0.0.1:<port>` or `localhost:<port>`, and WebSocket upgrades whose `Origin` is
not empty or one of those.

### Tunnel management

- One TLS 1.3 connection to `mesh.noqer.com:443`, ALPN `t3-mesh/1`, client
  certificate = agent identity, multiplexed with yamux.
- **Session order:** the hub orders an agent's sessions by its own accept time and
  routes new streams to the newest live one. Agents do not supply a generation, so
  an agent restart cannot confuse the order.
- **Network changes:** netlink route/address events on Linux, the system's
  network-change notification on macOS, and a 30 s DNS re-resolve as backup.
  On a change, or when the current tunnel's peer address is no longer in the set
  `mesh.noqer.com` resolves to (order and rotation are ignored), the agent opens a
  new session first. The old session drains its open streams for up to 10 minutes,
  then closes.
- **Liveness:** both sides ping every 10 s on the control stream. Three missed
  replies close the session on that side: the agent reconnects with exponential
  backoff and random jitter, capped at 30 s; the hub stops routing to it.
- **Sleep:** on wake, the network-change path runs immediately.

### Direct bypass

- The hub pushes a table of the machines this agent may reach: machine, services,
  LAN addresses, direct port, home status. It also pushes the rules and the
  revocation list. The agent caches all of it on disk.
- A connection on a link port goes direct when direct is enabled on both sides and
  the hub reports both machines home. The agent dials the peer's direct listener
  with mTLS (ALPN `t3-mesh-direct/1`), verifies the peer's certificate against the
  clients CA, checks that its URI SAN is the expected `agent-<machine>` and that the
  certificate is not revoked, and sends a header naming the service. The receiving
  agent checks the caller the same way, plus its cached rules, and answers with an
  accept line. Leaf fingerprints are not pinned, so renewal needs no coordination.
- **Setup deadline:** TCP connect, TLS handshake and the accept line share one 1 s
  deadline. A dial that fails or misses it falls back to the tunnel, so an address
  that accepts TCP but stalls cannot block the link. The failure is remembered for
  60 s for that peer.
- **Liveness:** direct connections use TCP keepalive (15 s idle, 3 probes at 5 s).
  On a network change or wake, the agent closes direct sessions whose local address
  is gone. Open streams never migrate between direct and tunnel paths; the T3 client
  reconnects its WebSocket and the new connection takes the current path.
- **Hub unreachable:** the agent cannot confirm home, so it tries the cached LAN
  addresses anyway. Identity checks make that safe on any network, and the dial
  fails fast when away. Cached rules allow direct traffic for at most 1 week after
  the last hub contact; after that, direct connections are refused.
- The direct listener runs only while the hub reports home, or while the hub is
  unreachable within the cache window.

### Platform notes

- **Key storage:** on every platform the key is a PEM file. The identity directory
  is owned by the service user, mode `0700`; the key is `0600`. The Keychain is not
  used: macOS ties Keychain access to the binary's code hash, so every unsigned
  self-update would prompt for access that an unattended agent cannot grant.
- **Accepted risk:** a file key can be copied by root or by anyone with the disk.
  FileVault on z-mac and full-disk encryption on devbox and z-arch cover the disk
  case; revocation covers the rest.
- No cgo is needed, so all binaries build with `CGO_ENABLED=0`.

### Self-update

- The hub advertises the desired version from its chart values. Renovate bumps it,
  so an agent rollout is an ordinary Argo CD sync.
- The agent downloads the release asset for its platform from GitHub releases and
  verifies a minisign signature over a manifest of version, platform and SHA-256.
  The agent embeds two trusted public keys (current and next). It refuses a version
  lower than the one it runs unless the hub explicitly marks a rollback.
- **Downloads:** `zekihan/t3-mesh` is a public repository, so agents fetch release
  assets anonymously; the signature, not the source, provides integrity.
- **Install layout:** `versions/<version>/t3-mesh-agent`, `current` and
  `known-good` symlinks. The service always starts a small launcher mode of the
  `known-good` binary, which runs `current`.
- **Probation:** after switching `current`, the new binary is on probation until it
  has, within 2 minutes of awake time during which the network is up and
  `mesh.noqer.com` answers TCP: completed `HelloAck`, bound every configured link
  port and (when home) the direct listener, and forwarded one test stream to each
  local `serve` target. Sleep and offline time do not count, so closing z-mac's lid
  mid-update is not a failure. Only then does it become `known-good`.
- **Rollback:** if the binary crashes, or the hub is reachable but the checks above
  do not pass in time, the launcher points `current` back at `known-good`, restarts
  it, and reports the failed version.
- **State compatibility:** a version on probation does not renew its certificate and
  does not rewrite on-disk state (identity, cached rules and peer table) in a format
  the previous version cannot read. A format change ships as read-new/write-old
  first, and the new format is written only by a later release after that one is
  `known-good` everywhere.
- **Failed versions:** the agent records failed versions on disk and never installs
  them again, whatever the hub advertises. The hub keeps no record of its own (it
  has no persistent state), so a hub restart cannot cause a retry loop.
- **Signing key:** minisign secret key in Doppler, synced to the `t3-mesh` repo's
  Actions secret by `terraform/doppler`. Rotation: ship the next public key as the
  second trusted key. From then on, every release manifest carries signatures from
  both keys, so an agent that missed the bridge release can still verify any later
  release with the old key and pick up the new trust set from it. The old key is
  retired only after the hub metrics show every agent on a version that trusts the
  new key. An agent that is still behind after that is recovered by a manual
  reinstall.

## Wire protocol

All messages on the control stream (the first stream the agent opens) are
length-prefixed JSON with a `type` field. The protocol version is in the ALPN.

| Message | Direction | Content |
|---|---|---|
| `Hello` | agent → hub | agent version, announced services, LAN addresses, direct port, cert fingerprint |
| `HelloAck` | hub → agent | home status, desired version and manifest URL, rules, peer table, revocation list |
| `Update` | hub → agent | new rules, peer table or revocation list after a change; agents re-check live sessions against it |
| `Ping` / `Pong` | both | liveness, round-trip time |
| `Renew` / `Renewed` | agent → hub / hub → agent | CSR / certificate and chain |
| `Status` | agent → hub | recent warnings, direct-session counts, failed update versions |
| `Enroll` / `Enrolled` | agent → hub / hub → agent | token + CSR / certificate and chain (unauthenticated connection only) |

Data streams start with one header line of JSON, then raw bytes:

- hub → agent: `{"svc":"t3","viewer":"z-phone"}` for viewer traffic, or
  `{"svc":"t3","from":"agent-z-arch"}` for relayed agent traffic;
- agent → hub: `{"to":"t3.devbox"}` for a link connection.

## Homelab changes

| Where | Change |
|---|---|
| `platform/cert-manager` | approver-policy, built-in approver disabled, one policy per issuer, hub policy, test that every issuer has a policy |
| `libs/mtls-policy` | kind `agent` with three identities; `mesh-t3-<machine>` entries listing viewers and permitted agents |
| `platform/t3-mesh` (new) | hub Deployment, Services, `IngressRouteTCP` for `mesh.noqer.com`, one `IngressRoute` per viewer host with the policy middleware (agents excluded) and viewer header, Let's Encrypt certificate, DNS records, RBAC, NetworkPolicy for 8443 and 8080, ConfigMap, vmalert rules, Gatus canaries |
| `apps/devbox` | removed at the M2 cutover |
| `terraform/doppler` | minisign key synced to the `t3-mesh` repo |
| `terraform/technitium` | LAN records for `mesh.noqer.com` and each viewer host, pointing at the Traefik VIP |
| CI | regenerate `gitops_pr.yaml` and `renovate.json` for the new chart |

## Observability

- Agents send status and warnings over the tunnel. The hub exports per-agent
  metrics: connected, path (LAN or OCI), open sessions, direct sessions,
  stream counts, version, certificate expiry, last seen.
- The hub logs agent events (connect, disconnect, path change, renewal, update,
  rollback, rejected peer) to stdout, so they reach VictoriaLogs.
- vmalert rules on the hub metrics alert on: an agent disconnected for more than
  10 minutes (24 hours for z-mac, which is often asleep), certificate expiry under
  14 days, and a failed self-update.
- Gatus probes alert when `canary-unauthorized` is accepted on a viewer host, or
  when a connection to `mesh.noqer.com` without a certificate, or with
  `canary-unauthorized`, gets anything other than a closed connection for a
  non-`Enroll` message.

## Security

| Threat | Control |
|---|---|
| Unauthenticated access to a machine | T3 binds to loopback. The only routes in are the tunnel (hub-authenticated agent, Traefik-authorized viewer) and the direct listener (mTLS + cached rules). T3 pairing remains. |
| Stolen phone or browser certificate | Reaches T3 login only; still needs T3 pairing. Cannot register as an agent. Revoke in `libs/mtls-policy`. |
| Agent certificate used as a viewer | Traefik middlewares exclude kind `agent`. |
| Local process or web page using a link port | Loopback only, `Host`/`Origin` checks against DNS rebinding, T3 pairing. Other local users are trusted (single-user machines). |
| In-cluster spoofing of PROXY v2 or viewer header | NetworkPolicy admits only Traefik on 8443 and 8080. |
| Stolen agent key | Revoke in `libs/mtls-policy`; the hub cuts the tunnel and relayed streams at once; peers close live direct sessions and refuse new ones as soon as they receive the update, and stop all direct traffic at the end of the cache window. The key file is readable only by the service user. |
| Compromised hub | Can mint only `agent-*` certificates (approver-policy). Can reach every agent's services, as any relay could. T3 pairing still applies. |
| Spoofed home status | Decided by the hub from the tunnel's source address, not by the agent. Traefik trusts PROXY headers only from frpc. A wrong guess during an outage only causes a failed, identity-checked dial. |
| Malicious update | minisign signature with embedded keys, dual-signed during key rotation, no downgrade except a hub-marked rollback to a signed release, automatic rollback. |
| Enrollment abuse | 15-minute single-use token bound to one identity, operator access via `kubectl exec`, rate limit, logging. |

## Rollout

| Milestone | Scope | Done when |
|---|---|---|
| M0 | approver-policy and per-issuer policies, nothing else | every existing certificate renews and a forced renewal of one Let's Encrypt and one clients certificate succeeds |
| M1 | hub, agent, tunnel, token enrollment; z-mac only | the phone opens `t3.z-mac.mesh.noqer.com` from mobile data, home and away; a forged PROXY header through the public path does not change the source the hub sees |
| M2 | devbox and z-arch on the mesh, link ports | the M2 gate below passes; then the hard switch below |
| M3 | direct bypass and outage mode | home links stay up with the hub scaled to zero |
| M4 | CSR renewal, self-update with rollback, integration test, metrics, vmalert rules and Gatus canaries | a forced renewal and a deliberately broken release both recover on z-mac |

**M2 gate (before the cutover), on real machines with real T3 through the full
frp/Traefik path:** the loopback-link open item is resolved; every machine links to
every other through loopback ports and pairs; a linked T3 WebSocket reconnects after
a tunnel switch and after z-mac sleeps and wakes; the phone reaches every machine as
a viewer, home and away. The in-process test uses a stand-in service and cannot
answer these.

**devbox cutover (end of M2), one change:** remove `apps/devbox` and the
`devbox.noqer.com` record, add `t3.devbox.mesh.noqer.com`, bind devbox's T3 to
`127.0.0.1`, then re-pair the phone and tablet and re-link every environment that
pointed at devbox. Clients on the old name break at the moment of the switch.

After each machine moves, turn T3 Connect off on it (`t3 up`) and bind T3 to
`127.0.0.1`.

## Testing

Unit tests in the `t3-mesh` repo: configuration parsing, rule evaluation,
revocation, path selection, session ordering, manifest verification, the link
port's `Host`/`Origin` checks and the launcher's rollback decision.

One in-process integration test runs a hub and two agents over loopback with a test
CA. It covers tunnel switching to a new session, direct connection and fallback to
the tunnel (including a peer that accepts TCP and stalls), direct connections across
a renewal, closing live sessions on revocation, and a deliberately broken update
that the launcher rolls back. A broken release can strand z-mac while it is
away, so this test runs in CI before every release.

The homelab side keeps its usual chart tests, plus one asserting that no rendered
Traefik middleware lists a kind `agent` identity.

## Open items

- **T3 behind a loopback port.** Confirm that a T3 link accepts
  `http://127.0.0.1:<port>` when the peer's `Host` header and origin differ from
  its own address, including origin checks, any URLs T3 advertises and WebSocket
  reconnects. If not, the agent rewrites `Host` (and `Origin` if needed) for link
  streams. Must be resolved before the M2 cutover.
- **Raw TCP services for viewers** (e.g. SSH). Traefik's HTTP policy middleware
  does not apply to TCP routes, so authorization for these would move into the hub.
  Out of scope for v1.
- **Repository creation.** `zekihan/t3-mesh` does not exist on GitHub yet; it will
  be public.

## Decision log

| Decision | Choice |
|---|---|
| Code location | new `zekihan/t3-mesh` repo; homelab holds the chart and policy |
| Scope | any named service; T3 first |
| Agent endpoint | Traefik TLS passthrough, the hub verifies agent certificates |
| Availability | one replica by design; multiple replicas are future work |
| Hostnames | `<svc>.<machine>.mesh.noqer.com`, agents dial `mesh.noqer.com` |
| Transport | TLS + yamux, ALPN `t3-mesh/1` |
| Viewer authorization | Traefik policy per host, agent identities excluded |
| T3 pairing | kept |
| Agent certificates | new `agent-*` identities with client and server usage |
| Machine-to-machine rules | `libs/mtls-policy` |
| Direct peer verification | clients CA, URI SAN, revocation list; no leaf pinning |
| Direct dial | one 1 s deadline for TCP, TLS and accept; TCP keepalive; no stream migration |
| Link port protection | loopback, `Host`/`Origin` checks |
| Machine registration | fixed list in the hub chart |
| Language | Go |
| Renewal | CSR through the hub |
| Key storage | `0600` file on every platform, including macOS (no Keychain) |
| CSR containment | approver-policy, per-issuer policies mirroring today |
| First certificate | single-use token + locally generated key |
| Home detection | hub, from the tunnel's source address |
| Hub outage | direct to cached LAN addresses for up to 1 week |
| Revocation | enforced by hub and agents on new and live sessions |
| Link ports | explicit in agent config |
| Updates | hub-pinned self-update from public GitHub releases, minisign signature, probation of 2 minutes of connected awake time covering hub, listeners and forwarding, auto-rollback, no renewal or state-format change on probation, failed versions recorded by the agent |
| Signing key | Doppler, two trusted keys, dual-signed manifests during rotation |
| PROXY trust | Traefik `trustedIPs` for frpc only; forged-header test in M1 |
| M2 cutover gate | real T3 linking, pairing, reconnect, sleep/wake and viewer access |
| Hub certificate | Let's Encrypt |
| Observability | through the hub to VictoriaMetrics and VictoriaLogs; vmalert for metric alerts, Gatus for canaries |
| Hub state | none persistent; tokens and last-seen lost on restart |
| Milestones | approver-policy first (M0), then M1–M4 |
| devbox cutover | hard switch |
| Testing | unit tests plus one in-process hub + two agents test |
