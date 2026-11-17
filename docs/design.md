# t3-mesh design

Status: accepted design; implementation in progress (M0 rolled out 2026-11-17). Date: 2026-11-16.

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

approver-policy approves a request when any one policy that selects it, and that the
requester may `use`, allows it. A narrower policy never vetoes a broader one, so
which account may `use` which policy is the whole control:

1. Install cert-manager approver-policy. Disable the built-in approver by appending
   `--controllers=*,-certificaterequests-approver` to the controller's existing
   `extraArgs` (which already carry the DNS-01 resolver flags), and only after the
   policies below are bound.
2. One `CertificateRequestPolicy` per existing issuer that allows the cert-manager
   controller exactly what it does today. For the clients Issuer that includes the
   common name `<profile>-<hostname>`, usages `digital signature` and `client auth`,
   and the existing identity URIs; omitted fields deny, so nothing may be left out.
   Only cert-manager's ServiceAccount may `use` these. A homelab chart test fails
   when an issuer has no policy.
3. One policy for the hub's ServiceAccount, selecting the clients Issuer by name,
   kind and group:
   - URI SANs limited to the configured agent URIs
     (`urn:noqer:mtls:clients:agent-devbox`, `-z-arch`, `-z-mac`, rendered from the
     machine list, no wildcard). approver-policy validates each value, not the list
     length, so "exactly one URI" is enforced by the hub, which rejects a CSR with
     more than one, and by `traefik-mtls-authz`, which rejects multi-URI leaves;
   - common name, DNS, IP and email fields omitted, so they are denied;
   - usages `client auth`, `server auth`, `digital signature`;
   - duration 8760h; ECDSA P-256 keys;
   - only the hub's ServiceAccount may `use` it, and the hub may `use` nothing else.
     Neither binding goes to a group such as `system:authenticated`.

The hub adds its own checks on top: the CSR carries exactly one URI SAN and nothing
else, the requested name must equal the requesting agent's own identity (or the
enrollment token's identity), the identity must be listed and not disabled, and the
CSR key must differ from the current one.

M0 proves the policies with a homelab render test that evaluates every existing
`Certificate` against the policy that will approve it, including the self-signed
root with `isCA` and every Let's Encrypt name shape, not only that each issuer has a
policy. A VictoriaLogs alert on approver-policy denial log lines catches anything
the test missed.

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
   the certificate and chain. The agent stores them and reconnects with the new
   identity. Which CAs it trusts for peers comes from the trust bundle below, not
   from this chain.

Enrollment uses its own ALPN, `t3-mesh-enroll/1`, without yamux: one `Enroll`
message of at most 4 KiB, one reply, then close, all within 30 s. The hub accepts a
connection without a client certificate only on that ALPN and only while an
enrollment token is outstanding; at all other times the handshake fails. Any other
message on such a connection closes it. The one exception is a client that offers no
ALPN at all, such as the Gatus TLS check: its handshake completes, so it sees the
public serving certificate, and the hub closes the connection without reading from
it. Enrollment is rate-limited per source
address, and every attempt is logged.

Enrollment is also the recovery path for an agent whose certificate expired, for
example after more than 30 days offline: the hub refuses the expired certificate, so
the operator issues a new token.

### Trust bundle

The hub sends agents a versioned trust bundle (the clients CA certificates it
accepts) in `HelloAck` and `Update`; agents cache it on disk and verify direct peers
against every CA in it. The bundle is its own ConfigMap in `platform/t3-mesh`
(`clients-ca-bundle`, with a revision), separate from the single issuing generation
`platform/mtls-pki` mounts, so it can hold two CAs at once; the hub verifies agent
tunnels against the same bundle. Rolling the clients CA:

1. Add the new CA to the bundle while the old one keeps issuing.
2. Wait until the hub's `/status` shows every agent has acknowledged that bundle
   revision.
3. Switch issuance to the new CA. Agents renew onto it over the following year.
4. Remove the old CA only after every agent certificate it signed has expired and
   the 1-week offline window has passed.

An agent that misses step 2 (offline throughout) still reaches the hub, which trusts
both CAs, and receives the new bundle on connect. One that misses everything until
the old CA is gone must be re-enrolled by the operator with a new token.

### Renewal

When less than 90 days remain, the agent generates a new key and sends a CSR over
its tunnel. Starting early (device certificates use 30 days) lets an agent that is
offline for weeks still renew without re-enrollment. It keeps the old key and certificate until
a new tunnel handshake with the new certificate succeeds, then deletes the old key.
Peers need no update, because direct connections do not pin leaf fingerprints. A
renewal that fails is retried hourly. An alert fires at 14 days left.

The hub logs the fingerprint of every certificate it obtains, and admits a tunnel
only with the newest issued leaf per agent identity (it lists its own
CertificateRequests to know which that is). An older leaf, for example one left
behind by a re-enrollment, is refused even before it expires.

The agent does not renew while a new version is on probation (see
[Self-update](#self-update)), so a rollback never meets an identity written by a
version that did not survive.

### Revocation

Disabled identities and blocked leaf fingerprints from `libs/mtls-policy` apply
everywhere. A fingerprint is lowercase hex SHA-256 of the leaf DER, as in
`traefik-mtls-authz`. A block lasts until the entry is removed: like the plugin, the
hub and agents ignore an entry's `expires` date, which is only a cleanup reminder.

- The hub refuses a revoked agent on connect and closes its existing tunnel when
  the policy changes.
- The hub pushes the revocation list to agents with the rules. Agents refuse a
  revoked peer on direct connections.
- Checks apply to live sessions, not only new ones. The hub tracks every relayed and
  viewer stream by source identity and leaf certificate; agents track every direct
  session by peer identity and certificate. When a revocation, a rule removal, the peer
  certificate's expiry or the end of the cache window makes a session no longer
  allowed, the hub or agent closes it at once. A long-lived T3 WebSocket therefore
  cannot outlive the permission that opened it.
- Removing an agent from the policy is the routine way to retire a machine.

## Hub

One Deployment in namespace `t3-mesh`, owned image pinned as `edge@sha256:`.

### Listeners

| Port | Reached through | Purpose |
|---|---|---|
| 8443 | Traefik `IngressRouteTCP`, `HostSNI(mesh.noqer.com)`, TLS passthrough, PROXY v2 | Agent tunnels and enrollment. The hub terminates TLS with its Let's Encrypt certificate and verifies agent certificates against the clients CA bundle. |
| 8080 | Traefik `IngressRoute` per viewer host, with the `mtls-clients` TLS option (as `apps/devbox` uses: require and verify a client certificate against the clients CA, strict SNI) and the `mesh-<svc>-<machine>` policy middleware | Viewer HTTP and WebSocket traffic. |
| 9090 | Gatus and kubelet probes | `/status`, `/alerts/<name>`, `/healthz`, `/readyz` (see [Observability](#observability)) |

`t3-mesh` is added to `platform/network-baseline`, so it starts default-deny for
ingress and egress. The chart's NetworkPolicy then allows:

- ingress from Traefik only, on 8443 and 8080: the hub trusts the PROXY v2 source on
  8443 (home detection, rate limits) and the viewer headers on 8080;
- ingress from Gatus on 9090 (kubelet probes are outside policy);
- egress to the Kubernetes API (the same API service and control-plane addresses
  Traefik's policy uses) and to kube-dns on TCP and UDP 53.

The hub's `mesh.noqer.com` certificate is a cert-manager Let's Encrypt certificate
like every other host. Agents verify it with system roots and the exact hostname.
The hub reloads the mounted certificate and clients CA bundle when they change, so
renewals need no restart.

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
homeCIDRs: [192.168.0.0/22, fd12:3456:789a:1::/64]  # LAN IPv4 and ULA; Technitium also answers AAAA
release:
  version: v0.3.0      # what agents should run; bumped by Renovate
```

Machine-to-machine rules come from the same `mesh-<svc>-<machine>` policy entries as
viewer rules: `agent-z-arch` in the `mesh-t3-devbox` identities list means z-arch's
agent may reach t3 on devbox. One list covers people and machines.

The list of machines and services is fixed. An agent announces what it serves; the
hub accepts only listed services and reports any difference in `/status` and as a
log event. The same list generates DNS records, certificates and Traefik routes.

The hub watches its mounted ConfigMap and applies changes live (rules, revocations,
desired version). The pod template carries no ConfigMap checksum, so a release bump
does not restart the hub or drop tunnels.

Kubernetes updates mounted ConfigMaps and Secrets by swapping a `..data` symlink, so
the hub watches each mount directory, not the files, and re-reads everything on any
event, plus every 60 s as a backstop. `/readyz` means only "can serve": listeners
up and configuration loaded once. Staleness never fails readiness, since pulling the
only replica from the Service would turn a late reload into an outage. Instead
`/alerts/stale-config` turns red when the loaded policy revision has differed from
the mounted one for more than 10 minutes, or the loaded serving certificate is
within 14 days of expiry while a newer one is mounted.

Traefik middlewares are rendered from the same policy entries with kind `agent`
filtered out, so an agent certificate is never accepted on a viewer host. Agent
identities in an entry only grant machine-to-machine access.

### Tunnel admission

The hub takes an agent's identity only from its certificate's URI SAN; `Hello` names
none. A tunnel is accepted only when that URI is exactly one configured
`agent-<machine>` identity, the identity is not disabled and the leaf is not
blocked. Any other certificate from the clients CA (a phone, a browser) gets the
connection closed before any stream is accepted, so it can never reach the relay
path, which bypasses the viewer controls.

The hub accepts the current and the previous tunnel protocol version (`t3-mesh/N`
and `t3-mesh/N-1` in ALPN), so agents on the previous release keep working while a
fleet update is in progress or rolled back.

### Routing

- **Viewer request:** the `traefik-mtls-authz` middleware sets three headers from
  the verified client certificate, after stripping any client-sent `X-Mtls-*`
  headers: `X-Mtls-Mesh-Viewer` (the full identity URI SAN, via the existing
  `forwardIdentityHeader`),
  `X-Mtls-Mesh-Fingerprint` (lowercase hex SHA-256 of the leaf DER, the same value
  the plugin matches against `blockedFingerprints`) and `X-Mtls-Mesh-Not-After`
  (leaf expiry, RFC 3339). The hub rejects a viewer request that lacks any of the
  three. The last two need a plugin extension (see
  [Homelab changes](#homelab-changes)). The hub records all three on every viewer
  stream, so it can close a stream when that identity is disabled, that leaf is
  blocked, a rule removes the viewer, or the leaf expires. It removes the headers
  before forwarding. The hub maps `Host` to `(machine, svc)`, opens a
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
Technitium publishes AAAA records to the IPv6 Traefik VIP (`fd12:3456:789a:1::81`)
for LAN names, so an agent at home may dial over either family; `homeCIDRs` lists
both LAN prefixes. The hub marks an agent home when its tunnel source is inside
`homeCIDRs` and tells
the agent in `HelloAck`. A café network that also uses `192.168.x` cannot fake
this, because its traffic arrives through frpc with a public source.

This holds only if the client cannot forge the PROXY header Traefik receives. On
`websecure-frp`, `proxyProtocol.trustedIPs` is the whole pod CIDR (never
`insecure`); what limits PROXY senders to frpc is Traefik's NetworkPolicy, which
admits only frpc to that port. Pinning frpc pod IPs instead would break on
rescheduling. The LAN entrypoint accepts no PROXY headers. M1 is not done until a
forged PROXY header sent through the public path, and a connection from a non-frpc
pod to `websecure-frp`, both fail to change the source the hub sees.

### Availability

One replica with `Recreate` rollout. A deploy or node drain drops tunnels for a few
seconds; agents reconnect with backoff, and home machines keep talking directly.
The hub is single-replica by design. Running two replicas would need shared session
ownership, ordering and distribution of rules and revocations, and is future work
with its own design.

### Kubernetes permissions

- `create`, `get`, `list`, `watch` CertificateRequests in `mtls-pki`, bound to the
  approver policy above (`list` finds the newest issued leaf per agent).
- `delete` CertificateRequests in `mtls-pki`, used only to prune its own older
  requests: those with its `managed-by` and identity labels, keeping the newest two
  per identity (never the newest issued one or one still in flight). RBAC cannot
  restrict `delete` by label, so this widens the hub's power to deleting other
  CertificateRequests in `mtls-pki`; cert-manager recreates them for live
  Certificates.
- Read its own ConfigMaps (configuration and `clients-ca-bundle`). Nothing else.

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
  t3.devbox: 127.0.0.1:27301
  t3.z-mac:  127.0.0.1:27302

direct:
  enabled: true                  # hub bypass while home
  port: 27400                    # bound only on addresses inside homeCIDRs
  cacheTTL: 168h                 # how long cached rules allow direct traffic
```

Link ports are explicit because T3 stores the URL; a port must never move. On each
machine, peers are linked with `t3 environment link http://127.0.0.1:<port>`. Link
and direct ports sit below both the Linux (32768–60999) and macOS (49152–65535)
ephemeral ranges, so an outgoing connection can never hold one.

Link ports are unauthenticated loopback listeners, so any local process on the
machine can use them; that is accepted on single-user machines. To block DNS
rebinding and cross-site requests from browsers, a link port rejects any request,
plain HTTP or WebSocket upgrade, whose `Host` is not `127.0.0.1:<port>` or
`localhost:<port>`, whose `Origin` is present and not one of those, or whose
`Sec-Fetch-Site` is present and not `same-origin` or `none` (which catches no-cors
GETs that carry no `Origin`). Native T3 clients send neither header and pass.

### Tunnel management

- One TLS 1.3 connection to `mesh.noqer.com:443`, ALPN `t3-mesh/1`, client
  certificate = agent identity, multiplexed with yamux.
- **Session order:** the hub orders an agent's sessions by its own accept time and
  routes new streams to the newest live one. Agents do not supply a generation, so
  an agent restart cannot confuse the order.
- **Network changes:** netlink route/address events on Linux, an `AF_ROUTE` socket
  on macOS (both work without cgo), and a 30 s DNS re-resolve as backup. An event
  alone does not replace the session, because container veths, VPNs, IPv6
  temporary-address rotation and Wi-Fi roams fire constantly. On an event the agent
  sends a ping with a 2 s deadline, and opens a new session only if the tunnel
  socket's local address is gone, that ping fails, or a lookup of `mesh.noqer.com`
  succeeds with a non-empty answer that does not contain the current peer address
  (order and rotation are ignored). A failed or empty lookup never replaces a
  session. A replaced session that still answers pings keeps its open streams until
  they end; one that does not is closed.
- **Liveness:** both sides ping every 10 s on the control stream. Three missed
  replies close the session on that side: the agent reconnects with exponential
  backoff and random jitter, capped at 30 s; the hub stops routing to it.
- **Sleep:** the agent detects wake by comparing wall-clock and monotonic time every
  5 s (no IOKit, so no cgo) and runs the network-change path immediately.

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
- **Hub unreachable:** the agent cannot confirm home, so it uses the gateway check
  below and, if it passes, tries the cached LAN addresses. Identity checks make a
  wrong guess safe, and the dial fails fast. Cached rules allow direct traffic for at most 1 week after
  the last hub contact; after that, direct connections are refused.
- The direct listener runs only while the hub reports home, or while the hub is
  unreachable within the cache window. It binds only local addresses inside
  `homeCIDRs`, never all interfaces. Because `192.168.0.0/22` is common on foreign
  networks too, a matching address is not enough while the hub is unreachable: the
  agent also requires the default gateway's MAC address to match the one it cached
  during its last hub-confirmed home session. Otherwise (a café, a hotspot) it does
  not listen and does not dial cached peers.
- Direct connections require TLS 1.3, so the client certificate is encrypted and
  never shown to a wrong host that answers on a peer's address.

### Platform notes

- **Key storage:** on every platform the key is a PEM file. The identity directory
  is owned by the service user, mode `0700`; the key is `0600`. The Keychain is not
  used: macOS ties Keychain access to the binary's code hash, so every unsigned
  self-update would prompt for access that an unattended agent cannot grant.
- **Accepted risk:** a file key can be copied by root or by anyone with the disk.
  FileVault on z-mac and full-disk encryption on devbox and z-arch cover the disk
  case; revocation covers the rest.
- No cgo is needed, so all binaries build with `CGO_ENABLED=0`. On macOS, Go uses
  the system resolver and certificate verifier through libSystem without cgo.
- **macOS risks to prove on z-mac (M1, and again after a self-update in M4):**
  Local Network privacy may block LAN dials from a non-root LaunchDaemon; the
  application firewall may drop inbound direct connections to a binary whose ad-hoc
  signature changes on every update; and with FileVault the daemon does not start
  after an unattended reboot until someone unlocks the disk, which is accepted.

### Self-update

- The hub advertises the desired version from its chart values in a `Release`
  message. Renovate bumps it, so an agent rollout is an ordinary Argo CD sync.
- The agent downloads the release asset for its platform from GitHub releases and
  verifies a minisign signature over a manifest of version, platform, SHA-256 and
  `minStateVersion` (the oldest release that can read the state this release
  writes). The agent embeds two trusted public keys (current and next). It refuses a
  version lower than the one it runs unless the hub's `Release` message allows a
  rollback, and always refuses a version older than the `minStateVersion` recorded
  in its state directory, whatever the hub says.
- **Preconditions:** the agent installs only while every local `serve` target
  accepts TCP and the running binary has received a `HelloAck` within the last
  minute. Otherwise it defers and checks again every 10 minutes, so a stopped T3 or
  an unhealthy hub never puts a release on probation.
- **Downloads:** `zekihan/t3-mesh` is a public repository, so agents fetch release
  assets anonymously; the signature, not the source, provides integrity. The agent
  builds every URL from the version and the compiled-in prefix
  `https://github.com/zekihan/t3-mesh/releases/download/`; the hub sends only a
  version, never a URL. The signing key is an environment-scoped secret available
  only to the release environment; a tag ruleset limits who can push release tags,
  and the workflow refuses a tag whose commit is not an ancestor of `main`.
- **One fleet version:** all agents follow one `release.version`; there is no
  staged rollout. The previous-protocol rule in [Tunnel admission](#tunnel-admission)
  and per-machine rollback cover a bad release.
- **Install layout:** `versions/<version>/t3-mesh-agent`, `current` and
  `known-good` symlinks. The service always starts a small launcher mode of the
  `known-good` binary, which runs `current`. A `previous-good` symlink keeps the
  release before `known-good`. Before starting a new binary, the launcher waits for
  the old one to exit, so link ports are free.
- **Launcher updates:** the launcher is part of every release, so it is vetted too.
  During probation the new binary runs `launcher --self-test`, which supervises a
  dummy child through start, health pipe, crash and rollback. After promotion the
  launcher re-execs itself from the new `known-good`; the re-exec restarts the agent
  child (a few seconds of link interruption) rather than adopting it. If the new
  launcher still fails, a fallback repoints `known-good` to `previous-good`: on
  Linux an `OnFailure=` unit triggered when systemd's start limit is hit, on macOS a
  second LaunchDaemon that runs the `previous-good` binary every 5 minutes and
  repoints when the main daemon's heartbeat file is older than 5 minutes.
- **Local startup check:** within 30 s of starting, independent of the hub, the new
  binary must load its cached state, bind every configured link port and the direct
  listener when cached state calls for it, and answer the launcher on a health pipe
  (and keep answering every 10 s). Failing this triggers rollback at once, so a
  binary that hangs during a hub outage cannot keep direct access down.
- **Probation:** after that, the new binary is on probation until it has, within
  2 minutes of awake time during which the network is up and the hub completes a
  TLS handshake on `mesh.noqer.com` (the hub terminates TLS, so its process is up):
  completed `HelloAck`, opened one test connection directly to each local `serve`
  target (a local dial, not a relay through the hub, which has no rule for an agent
  reaching its own machine), re-fetched and verified its own release manifest (so
  the updater itself works), and passed the launcher self-test.
  Sleep, offline time and hub downtime do not count, so closing z-mac's lid
  mid-update is not a failure. Only then does it become `known-good`.
- **Rollback:** if the binary crashes, fails the local startup check, or does not
  pass probation in time, the launcher points `current` back at `known-good`,
  restarts it, and reports the failed version and reason.
- **State compatibility:** a version on probation does not renew its certificate and
  does not rewrite on-disk state (identity, cached rules, peer table, trust bundle)
  in a format the previous version cannot read. A format change ships as
  read-new/write-old first, and the new format is written only by a later release
  after that one is `known-good` everywhere. When a `known-good` release first
  writes a new format, it records its manifest's `minStateVersion` in the state
  directory; no release older than that is ever started again, including by a
  hub-allowed rollback.
- **Failed versions:** a crash, a failed local startup check, a failed manifest
  re-fetch or launcher self-test, or a `Reject` from the hub naming the version is a
  release failure: the agent records the version on disk and never installs it
  again, whatever the hub advertises. A missing `HelloAck` without a `Reject`, or a
  failed test connection to a `serve` target that accepted TCP before install, is a
  dependency failure: the agent rolls back but retries the version after 1 hour,
  and records it as failed only after 3 such attempts. A disabled identity or a bad
  policy therefore cannot blacklist a good release. The hub keeps no record of its own (it has no persistent state),
  so a hub restart cannot cause a retry loop.
- **Signing key:** minisign secret key in Doppler, synced to the `t3-mesh` repo's
  Actions secret by `terraform/doppler`. Rotation: ship the next public key as the
  second trusted key. From then on, every release manifest carries signatures from
  both keys, so an agent that missed the bridge release can still verify any later
  release with the old key and pick up the new trust set from it. The old key is
  retired only after the hub's `/status` shows every agent on a version that trusts
  the new key. An agent that is still behind after that is recovered by a manual
  reinstall.

## Wire protocol

All messages on the control stream (the first stream the agent opens) are
length-prefixed JSON with a `type` field. The protocol version is in the ALPN.

| Message | Direction | Content |
|---|---|---|
| `Hello` | agent → hub | agent version, announced services, LAN addresses, direct port, cert fingerprint |
| `HelloAck` | hub → agent | home status, `Release`, rules, peer table, revocation list, trust bundle |
| `Update` | hub → agent | new rules, peer table, revocation list or trust bundle after a change; agents re-check live sessions against it |
| `Release` | hub → agent | desired version, rollback allowed, revision; sent in `HelloAck` and again whenever the chart value changes |
| `Ping` / `Pong` | both | liveness, round-trip time |
| `Renew` / `Renewed` | agent → hub / hub → agent | CSR / certificate and chain |
| `Reject` | hub → agent | reason (identity disabled, leaf not newest, unsupported version, other) before closing a session |
| `Status` | agent → hub | recent warnings, direct-session counts, running version, last applied `Release`, policy, revocation and trust-bundle revisions, failed update versions and reasons |
| `Enroll` / `Enrolled` | agent → hub / hub → agent | token + CSR / certificate and chain (ALPN `t3-mesh-enroll/1` only) |

Data streams start with one header line of JSON, then raw bytes:

- hub → agent: `{"svc":"t3","viewer":"z-phone"}` for viewer traffic, or
  `{"svc":"t3","from":"agent-z-arch"}` for relayed agent traffic;
- agent → hub: `{"to":"t3.devbox"}` for a link connection.

## Homelab changes

| Where | Change |
|---|---|
| `platform/cert-manager` | approver-policy, built-in approver disabled by appending to the existing `extraArgs`, one policy per issuer usable only by cert-manager, hub policy usable only by the hub, test that every issuer has a policy |
| `platform/network-baseline` | `t3-mesh` added to the default-deny namespace list |
| `libs/mtls-policy` | kind `agent` with three identities; `mesh-t3-<machine>` entries listing viewers and permitted agents |
| `libs/app` | a kind filter in `templates/_policy.tpl`, so rendered Traefik middlewares drop kind `agent` |
| `zekihan/traefik-mtls-authz` | options to forward the leaf SHA-256 fingerprint and expiry in `X-Mtls-*` headers, under the same name validation and stripping as `forwardIdentityHeader`, with tests; homelab bumps the plugin version |
| `platform/t3-mesh` (new) | hub Deployment, Services, `IngressRouteTCP` for `mesh.noqer.com`, one `IngressRoute` per viewer host with the `mtls-clients` TLS option, the policy middleware (agents excluded) and viewer headers, Let's Encrypt certificate, DNS records, RBAC, NetworkPolicy (ingress 8443/8080 from Traefik, 9090 from Gatus; egress to the API and DNS), ConfigMap, `clients-ca-bundle` ConfigMap, Gatus endpoints; chart tests that every viewer route uses `mtls-clients` and the policy middleware (without it, client-sent `X-Mtls-*` headers would reach the hub) and that no middleware lists an `agent-*` URI |
| `apps/devbox` | removed at the M2 cutover |
| `platform/traefik` | regenerate the backend-ports file for the hub's 8443 and 8080; at the M2 cutover, drop the `192.168.2.71:3773` devbox `lanPeers` entry in the same change |
| `terraform/doppler` | minisign key synced to the `t3-mesh` repo |
| `terraform/technitium` | LAN A and AAAA records for `mesh.noqer.com` and each viewer host, pointing at the Traefik VIPs. A `mesh.noqer.com` zone is authoritative for its whole subtree, so every viewer record lives in it and the zone is created with all of them in one change; a missing record would be NXDOMAIN at home |
| CI | regenerate `gitops_pr.yaml` and `renovate.json` for the new chart |

## Observability

The cluster has no metrics scraper or vmalert, so the hub evaluates its own alert
conditions and Gatus probes them. Nothing new is added to the cluster for this.

- **`/status`** (JSON) lists, per agent: connected, path (LAN or OCI), open and
  direct sessions, stream counts, version, certificate expiry, last seen, and the
  last acknowledged `Release`, policy, revocation and trust-bundle revisions. Rotation
  steps that wait for "every agent acknowledged" read it.
- **`/alerts/<name>`** returns 200 when fine and 503 when firing, one Gatus endpoint
  each: `agent-<machine>-disconnected` (more than 10 minutes, 24 hours for z-mac,
  which is often asleep; counted from hub start after a restart),
  `agent-<machine>-cert-expiry` (under 14 days), `agent-<machine>-update-failed`, and
  `stale-config`.
- The hub logs agent events (connect, disconnect, path change, renewal, issued
  fingerprint, update, rollback, reject, rejected peer) to stdout, so they reach
  VictoriaLogs.
- Gatus canaries: `canary-unauthorized` must be refused on every viewer host, and a
  TLS check on `mesh.noqer.com` confirms the hub serves its certificate. A Gatus
  probe cannot speak the tunnel protocol, so rejection of unauthenticated or
  non-agent tunnel connections is covered by the integration test and by M1.

## Security

| Threat | Control |
|---|---|
| Unauthenticated access to a machine | T3 binds to loopback, LAN mode is off, and pre-existing non-mTLS proxies (z-arch's `caddy-t3.service`) are removed. The only routes in are the tunnel (hub-authenticated agent, Traefik-authorized viewer) and the direct listener (mTLS + cached rules). T3 pairing remains. |
| Stolen phone or browser certificate | Reaches T3 login only; still needs T3 pairing. Cannot register as an agent or open a tunnel (tunnel admission accepts configured agent URIs only). Revoke in `libs/mtls-policy`. |
| Agent certificate used as a viewer | Traefik middlewares exclude kind `agent`. |
| Local process or web page using a link port | Loopback only, `Host` and `Origin` checks on every request against DNS rebinding and cross-site requests, T3 pairing. Other local users are trusted (single-user machines). |
| Direct listener exposed off the LAN | Binds only addresses inside `homeCIDRs`, and during a hub outage only when the default gateway's MAC matches the cached home gateway. TLS 1.3 only. |
| In-cluster spoofing of PROXY v2 or viewer header | NetworkPolicy admits only Traefik on 8443 and 8080. |
| Stolen agent key | Revoke in `libs/mtls-policy`; the hub cuts the tunnel and relayed streams at once; peers close live direct sessions and refuse new ones as soon as they receive the update, and stop all direct traffic at the end of the cache window. The key file is readable only by the service user. |
| Compromised hub | Can mint only the configured agent certificates (approver-policy). Can reach every agent's services, as any relay could. T3 pairing still applies. |
| Spoofed home status | Decided by the hub from the tunnel's source address, not by the agent. Traefik trusts PROXY headers only from frpc. A wrong guess during an outage only causes a failed, identity-checked dial. |
| Malicious update | minisign signature with embedded keys, dual-signed during key rotation, download URL fixed in the binary, no downgrade except a hub-marked rollback to a signed release, automatic rollback. Accepted risk: a compromised hub or chart value can roll every agent back to any older signed release at or above `minStateVersion`, including one with a known flaw. |
| Enrollment abuse | 15-minute single-use token bound to one identity, operator access via `kubectl exec`, certificate-less connections only on the enrollment ALPN while a token is outstanding, size and time limits, rate limit, logging. |
| Old agent leaf after renewal or re-enrollment | Hub admits only the newest issued leaf per identity; issued fingerprints are logged. |
| T3 trusting loopback clients | Every viewer and peer reaches T3 from `127.0.0.1`. The M1/M2 gates prove that an unpaired request through the agent gets nothing a remote unpaired client would not. |

## Rollout

| Milestone | Scope | Done when |
|---|---|---|
| M0 | approver-policy and per-issuer policies, plus the `t3-mesh` namespace, hub ServiceAccount and hub policy (no workload) | the render test passes and every existing certificate renews; a forced renewal of one Let's Encrypt and one clients certificate succeeds; CertificateRequests from the hub ServiceAccount for `urn:noqer:mtls:clients:z-phone`, and for `agent-z-mac` with an added DNS SAN, are denied by the hub policy and get no certificate |
| M1 | `traefik-mtls-authz` extension released and deployed first; then hub, agent, tunnel, token enrollment, live viewer revocation, Gatus canaries and `/status`; z-mac only, with its T3 bound to `127.0.0.1` and LAN mode off before the checks | the phone opens `t3.z-mac.mesh.noqer.com` from mobile data, home and away; a forged PROXY header through the public path, or from a non-frpc pod, does not change the source the hub sees; z-mac at home resolves `mesh.noqer.com` to the LAN VIP and is marked home over both IPv4 and IPv6; an unpaired request through the agent gets nothing a remote unpaired client would not; the macOS risks in [Platform notes](#platform-notes) are checked; blocking the phone's leaf closes its open WebSocket |
| M2 | devbox and z-arch on the mesh, link ports | the M2 gate below passes; then the hard switch below |
| M3 | direct bypass, outage mode, live direct-session revocation | home links stay up with the hub scaled to zero; revoking a peer closes its open direct session; z-mac on a foreign `192.168.x` network with the hub blocked does not listen |
| M4 | CSR renewal, trust bundle, self-update with rollback and launcher fallback, integration test, Gatus alert endpoints | a forced renewal and a deliberately broken release (agent and launcher) both recover on z-mac; the macOS checks pass again after the update |

**M2 gate (before the cutover), on real machines with real T3 through the full
frp/Traefik path:** z-arch moves first: its T3 is bound to `127.0.0.1` with LAN mode
(`T3CODE_LAN`) off, and `caddy-t3.service` and the `NODE_EXTRA_CA_CERTS` drop-in are
removed. devbox stays LAN-bound until the cutover because the old route needs it,
so the loopback checks are proven on z-arch and z-mac. Then: the loopback-link and
loopback-trust open items are resolved; every machine links to
every other through loopback ports and pairs; a linked T3 WebSocket reconnects after
a tunnel switch and after z-mac sleeps and wakes; the phone reaches every machine as
a viewer, home and away. The in-process test uses a stand-in service and cannot
answer these.

**devbox cutover (end of M2), one change:** remove `apps/devbox`, its Traefik
`lanPeers` entry and the
`devbox.noqer.com` record, add `t3.devbox.mesh.noqer.com`, bind devbox's T3 to
`127.0.0.1`, then re-pair the phone and tablet and re-link every environment that
pointed at devbox. Clients on the old name break at the moment of the switch.

After each machine moves, turn T3 Connect off on it (`t3 up`), bind T3 to
`127.0.0.1`, turn LAN mode off, and remove any other proxy or listener that reaches
T3 without mTLS.

## Testing

Unit tests in the `t3-mesh` repo: configuration parsing, rule evaluation,
revocation, path selection, session ordering, manifest verification, the link
port's `Host`/`Origin` checks and the launcher's rollback decision.

One in-process integration test runs a hub and two agents over loopback with a test
CA. It covers tunnel switching to a new session, direct connection and fallback to
the tunnel (including a peer that accepts TCP and stalls), direct connections across
a renewal, closing live sessions on revocation (direct, relayed and viewer, including
a single blocked leaf), a `Release` change reaching a connected agent, a CA rollover
through the trust bundle, and broken updates that the launcher rolls back: one that
crashes, one that hangs before binding link ports while the hub is down, and one
whose only failure is a stopped `serve` target (retried, not blacklisted). It
also checks that a phone certificate cannot open a tunnel, that a certificate-less
connection is refused when no token is outstanding, that an older leaf is refused
after renewal, that a failed DNS lookup or an unrelated network event keeps the
session, that a link port refuses a request with a foreign `Origin` or
`Sec-Fetch-Site`, that a broken launcher falls back to `previous-good`, that a
missing `HelloAck` is retried rather than blacklisted, and that a stale config turns
`/alerts/stale-config` red without failing `/readyz`.
A broken release can strand z-mac while it is away, so this test runs in CI before
every release.

The homelab side keeps its usual chart tests, plus one asserting that no rendered
Traefik middleware lists a kind `agent` identity.

## Open items

- **T3 behind a loopback port.** Confirm that a T3 link accepts
  `http://127.0.0.1:<port>` when the peer's `Host` header and origin differ from
  its own address, including origin checks, any URLs T3 advertises and WebSocket
  reconnects. If not, the agent rewrites `Host` (and `Origin` if needed) for link
  streams. Must be resolved before the M2 cutover.
- **T3 trust of loopback clients.** After the move every request reaches T3 from
  `127.0.0.1`. Confirm T3 grants loopback clients nothing beyond what pairing grants
  (the `t3 auth`/`t3 pair` control plane is local), and that T3 with LAN mode off
  accepts a non-local `Host` such as `t3.devbox.mesh.noqer.com`. If either fails,
  the design needs a change before M1 is done.
  Checked 2026-11-17 on z-arch (Linux, T3 0.1.11 nightly) with a separate instance
  bound to `127.0.0.1` and LAN mode off: its auth policy is `loopback-browser`, the
  only bootstrap method is a one-time token, an unauthenticated loopback request with
  `Host` and `Origin` set to `t3.z-mac.mesh.noqer.com` is accepted and gets the same
  `auth_invalid` (401) answers on every `/api/` route as an unpaired LAN client of
  the LAN-mode instance, and the WebSocket needs a ticket. M1 repeats the check on
  z-mac.
  On z-mac (2026-11-17), where T3 is the desktop app, all 196 `/api/` routes answer
  identically through the mesh and from a remote LAN client. With
  `serverExposureMode: local-only` the desktop backend binds `127.0.0.1` and reports
  the `desktop-managed-local` policy, whose advertised bootstrap method is
  `desktop-bootstrap` only. A viewer still pairs with a one-time token minted on the
  machine with `t3 auth pairing create --base-url https://t3.z-mac.mesh.noqer.com`,
  because the server accepts any unexpired one-time token regardless of policy; the
  in-app pairing UI does not offer this in local-only mode. The hub sends
  `X-Forwarded-Proto: https` so T3 marks its session cookie `Secure`.
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
| Viewer identity to hub | `X-Mtls-Mesh-*` headers for identity, leaf DER SHA-256 and expiry, all required; plugin extended for the last two; `mtls-clients` TLS option on every viewer route |
| T3 pairing | kept |
| Agent certificates | new `agent-*` identities with client and server usage |
| Machine-to-machine rules | `libs/mtls-policy` |
| Direct peer verification | clients CA, URI SAN, revocation list; no leaf pinning |
| Direct dial | one 1 s deadline for TCP, TLS and accept; TCP keepalive; no stream migration |
| Link port protection | loopback, `Host`, `Origin` and `Sec-Fetch-Site` checks on every request; ports below the ephemeral ranges |
| Direct listener binding | only addresses inside `homeCIDRs` |
| Service manager | systemd unit (user `t3mesh`) on Linux, LaunchDaemon (user `_t3mesh`) on macOS, outside the login session |
| Machine registration | fixed list in the hub chart |
| Language | Go |
| Renewal | CSR through the hub |
| Key storage | `0600` file on every platform, including macOS (no Keychain) |
| CSR containment | approver-policy; per-issuer policies mirroring today usable only by cert-manager; hub policy with exact agent URIs usable only by the hub |
| First certificate | single-use token + locally generated key |
| Home detection | hub, from the tunnel's source address; IPv4 and IPv6 LAN prefixes |
| CertificateRequest cleanup | hub prunes its own, keeps newest two; RBAC delete in mtls-pki |
| Agent CA trust | versioned `clients-ca-bundle` ConfigMap pushed by the hub, overlapping CAs during rollover, operator re-enrollment for agents that miss it |
| Hub outage | direct to cached LAN addresses for up to 1 week |
| Revocation | enforced by hub and agents on new and live sessions |
| Link ports | explicit in agent config |
| Updates | hub-pinned self-update via a live `Release` message, public GitHub releases, minisign signature, install only while local services and the hub are healthy, hub-independent local startup check, 2-minute probation counted only while the hub is up and covering manifest re-fetch and launcher self-test, auto-rollback, no renewal or state-format change on probation, `minStateVersion` floor on rollbacks, release failures (including hub `Reject`) blacklisted, dependency failures (including missing `HelloAck`) retried |
| Signing key | Doppler, environment-scoped secret, tag ruleset and ancestor-of-main check, two trusted keys, dual-signed manifests during rotation |
| PROXY trust | Traefik `trustedIPs` = pod CIDR, limited to frpc by NetworkPolicy; forged-header and non-frpc-pod tests in M1 |
| Tunnel admission | certificate URI must be exactly one configured agent identity |
| Hub namespace network | default-deny baseline plus explicit ingress and egress |
| Config reload | watch mount directories, periodic re-read, `/alerts/stale-config` on stale state |
| Downgrades | hub flag allows any signed release at or above `minStateVersion` (accepted risk); download URL fixed in the binary |
| M2 cutover gate | real T3 linking, pairing, reconnect, sleep/wake and viewer access |
| Hub certificate | Let's Encrypt |
| Observability | hub `/status` and `/alerts/*` probed by Gatus; events to VictoriaLogs; no scraper or vmalert added |
| Readiness | `/readyz` means can serve; staleness is an alert, never unready |
| Network-change handling | probe before replacing; healthy sessions keep their streams |
| Fleet rollout | one global version, no staging; hub accepts current and previous protocol |
| Launcher | vetted by self-test in probation; `previous-good` fallback via systemd `OnFailure` / macOS fallback daemon |
| Direct listener during outage | also requires the cached home gateway MAC; TLS 1.3 only |
| Enrollment surface | own ALPN, only while a token is outstanding, size and time limits |
| Agent renewal | at 90 days left; hub admits only the newest leaf per identity |
| T3 on machines | loopback-bound, LAN mode off, other non-mTLS proxies removed before the gates |
| Hub state | none persistent; tokens and last-seen lost on restart |
| Milestones | approver-policy first (M0), then M1–M4 |
| devbox cutover | hard switch |
| Testing | unit tests plus one in-process hub + two agents test |
