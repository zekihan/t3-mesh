# t3-mesh design

Status: accepted design; implemented (M0 to M4 done 2026-11-17). Date: 2026-11-16.
Device enrollment for the Android app (hub 0.2.0) is described under
[Enrolled-device identities](#enrolled-device-identities), [Device enrollment](#device-enrollment)
and [Device renewal](#device-renewal). Direct connection of an enrolled device to a
machine at home (agent and hub 0.3.0) is described under
[Direct device access](#direct-device-access).

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
  doing so through a cluster outage. An enrolled phone at home does the same.
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
| Enrolled device at home | a machine at home | LAN → the machine's device listener (mTLS, HTTP/1.1) → `127.0.0.1:3773`, with no hub on the path |

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

### Enrolled-device identities

The Android app (see the fork's `docs/android-fork.md`, item 4) enrolls with a key
that lives in the Android Keystore and then uses its own identity on the `mesh-*`
hosts. `libs/mtls-policy` gains a kind `enrolled device` for these identities, and
the hub config lists them under `devices` (see [Configuration](#configuration)).

- **Name.** `device-<name>-mesh`, matching
  `^device-[a-z0-9]+(-[a-z0-9]+)*-mesh$` and at most 40 characters, with the URI SAN
  `urn:noqer:mtls:clients:<name>`. The first two are `device-z-phone-mesh` and
  `device-z-tablet-mesh`. One identity per device, so one device's renewal never
  supersedes the other's.
- **Disjoint namespaces.** A device name never starts with `agent-` and never equals
  an existing device identity (`z-phone`, `z-tablet`, `z-arch`, `z-mac`), so the
  kind of an identity follows from its name alone, and the hub derives the usages it
  requests from it. The hub refuses an overlap between `devices` and the agent
  identities in its config.
- **Reach.** An enrolled device appears only in `mesh-*` policy entries (a chart test
  fails when any other entry lists one) and under `api.identities`. A compromised
  hub, which can mint these identities and nothing else, therefore reaches only the
  mesh viewers, which it already proxies. It can never mint `z-phone`, which every
  app policy trusts, and a KeyChain identity is refused by every endpoint that is
  for devices only.
- **Certificates.** `client auth` and `digital signature`, never `server auth`: a
  device is a client of every host it uses. The hub requires the same of the leaf it
  gets back and hands out no other.

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

4. A second policy for the same ServiceAccount, selecting the same clients Issuer,
   for enrolled devices:
   - URI SANs limited to the enumerated device URIs
     (`urn:noqer:mtls:clients:device-z-phone-mesh`, `-z-tablet-mesh`, no wildcard);
   - common name, DNS, IP and email fields omitted;
   - usages `client auth` and `digital signature` only, never `server auth`;
   - duration 8760h, ECDSA P-256 keys, not a CA.

   approver-policy approves a request when one policy allows all of it, so a request
   that mixes an agent's usages or URI with a device's is denied by both. The agent
   policy is unchanged. The hub's ClusterRole gains `use` on the second policy by name,
   and the hub may still `use` nothing else.

What the hub sends, by kind. The hub requests usages by the kind of the identity (a
CertificateRequest never mixes them, and none is created when the CSR's URI is not
the requested identity), and always the same everything else:

| `CertificateRequest` field | Agent (`agent-<machine>`) | Enrolled device (`device-<name>-mesh`) |
|---|---|---|
| `metadata.generateName` | `t3-mesh-<identity>-` | `t3-mesh-<identity>-` |
| `metadata.labels` | `t3-mesh.noqer.com/identity: <identity>`, `app.kubernetes.io/managed-by: t3-mesh-hub` | the same |
| `spec.issuerRef` | `issuer.name`, `kind`, `group` from the hub config (`clients`, `Issuer`, `cert-manager.io`), in namespace `issuer.namespace` (`mtls-pki`) | the same |
| `spec.usages` | `client auth`, `server auth`, `digital signature` | `client auth`, `digital signature` |
| `spec.duration` | `8760h0m0s` | `8760h0m0s` |
| `spec.isCA` | omitted (false) | omitted (false) |
| `spec.request` | PEM CSR: ECDSA P-256, empty subject, exactly one URI SAN equal to the identity URI, no DNS, IP or email SAN | the same, and no requested extension other than the URI SAN |

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
   enroll-token agent-z-mac`, or, for an enrolled device,
   `... enroll-token --device device-z-phone-mesh`. This CLI mode does not hold tokens itself: it asks the
   running hub over an admin unix socket inside the pod (`/run/t3-mesh/admin.sock`,
   mode `0600`, not exposed on any port). The hub prints a single-use token bound to
   that identity, valid for 15 minutes, held hashed in the server's memory. A hub
   restart invalidates outstanding tokens. The argument is an agent identity, and
   `--device` takes an identity listed under `devices`; each refuses the other kind and
   every unknown or disabled identity, so a token is never minted for the wrong kind.
   (The admin request carries `kind` as `agent` or `device`; one without it is an
   agent request, as sent by earlier releases.)
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
the operator issues a new token. It is the recovery path for a device too: one that
lost a renewal reply holds a superseded leaf and re-enrolls with a new token.

#### Device enrollment

A device enrolls over the same ALPN and with the same two messages, so the app
speaks only this section. It connects to `mesh.noqer.com:443` without a client
certificate, offering ALPN `t3-mesh-enroll/1`, and verifies the hub's Let's Encrypt
certificate with system roots and the exact hostname. Each message is a 4-byte
big-endian length followed by that many bytes of JSON, and the request is at most
4 KiB. The app creates a non-exportable ECDSA P-256 key, builds a CSR with the
identity URI as its only SAN and an empty subject (no other extension), and sends:

```json
{"type":"Enroll","body":{"token":"<token>","csr":"-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----\n"}}
```

On success the reply is:

```json
{"type":"Enrolled","body":{"certificate":"<PEM leaf>","chain":"<PEM issuer chain>","caBundle":"<PEM, one or more clients CA certificates>","caRevision":"<opaque string>"}}
```

`certificate` is exactly one certificate; `chain` is the issuing CA (the issuer's
`status.ca`); `caBundle` is the clients CA bundle the hub trusts, which holds two CAs
during a rollover, and `caRevision` its revision. Agents ignore the two `caBundle`
fields (they get the same bundle in `HelloAck`), and a release before device
enrollment omits them. Any failure is one `{"type":"Reject","body":{"reason":"enroll-failed","detail":"<short text>"}}`
and a close. The checks run in this order: the CSR is validated first (signature,
ECDSA P-256 key, empty subject, exactly one URI SAN, no DNS, IP or email SAN, no extra
requested extension for a device), so a malformed request cannot burn a token; then the
token is redeemed (single use, bound to one identity, which must be the CSR's);
then the hub's `EnrollAllowed` admits the identity (a configured agent, or a device
listed under `devices`, and not disabled); then the certificate is requested. A
device is issued a certificate with `client auth` only, which the hub verifies before it
replies. A token for one device cannot enroll the other, and a device token cannot enroll
an agent identity or the other way round. Enrollment is rate limited per source address
(5 attempts in 10 minutes) and every attempt is logged with the enrolled URI.

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

An enrolled device renews through the hub API instead, see
[Device renewal](#device-renewal). The rest of this section is about agents.

When less than 90 days remain, the agent generates a new key and sends a CSR over
its tunnel. Starting early (device certificates use 30 days) lets an agent that is
offline for weeks still renew without re-enrollment. An operator forces a renewal
by creating `renew-now` in the agent's state directory; the agent renews on its next
check (hourly, or at once after a restart) and deletes the file. It keeps the old key and certificate until
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

The same newest-leaf rule holds for enrolled devices on the viewer hosts and the API,
as [Newest leaf for devices](#newest-leaf-for-devices) describes.

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
- Removing an agent from the policy is the routine way to retire a machine. Removing
  a device from `devices` (and from the policy entries) retires a device: its open
  streams close and every agent drops its leaf.
- A disabled device identity or a blocked device leaf is refused on enrollment, the
  viewer hosts and the API like any other identity.

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
api:
  host: hub.mesh.noqer.com   # optional; defaults to hub.<viewerDomain>
  # The `mesh-hub` callers: the KeyChain identities and the enrolled devices.
  identities: [z-phone, z-tablet, device-z-phone-mesh, device-z-tablet-mesh]
devices: [device-z-phone-mesh, device-z-tablet-mesh]  # optional; enrolled devices allowed to enroll and renew
```

`devices` is the list of enrolled-device identities that may enroll and renew, rendered
by the chart from the policy entries of kind `enrolled device`. Each must match
`^device-[a-z0-9]+(-[a-z0-9]+)*-mesh$` (at most 40 characters) and must not be an agent
identity. Unknown fields are rejected, as everywhere in this file. When it is absent
there is no device enrollment: no token is minted, no enrollment is admitted and no
device leaf is admitted. `devices` is a separate field, like `api.identities`: it is
never a rule. Deploy order is the same as for `api`: the hub release that understands
`devices` ships first, and the chart change that renders it after it.

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
blocked. Any other certificate from the clients CA (a phone, a browser, an enrolled device)
gets the connection closed before any stream is accepted, so it can never reach the
relay path, which bypasses the viewer controls.

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

### Hub API

`hub.mesh.noqer.com` (`api.host`, default `hub.<viewerDomain>`) is served by the
viewer listener on 8080. The listener matches this host before it maps `Host` to
`(machine, svc)`; any other host goes through that mapping as before. `mesh.noqer.com`
stays agent-only.

Admission is the viewer-stream admission: the three `X-Mtls-Mesh-*` headers are
required and parsed the same way, an agent identity is refused, and a disabled
identity, a blocked leaf or an expired leaf gets `403`. The caller must also be listed
under `api.identities`, so a valid client certificate that is not a device listed
there gets `403` too. `api.identities` is its own field. It is never a rule: the rule
map accepts only `mesh-<svc>-<machine>` entries and feeds the agents. A name beginning
`agent-` is invalid there, and `api.host` may not equal `viewerDomain` or sit under it
as a viewer host.

Every endpoint but `renew` is `GET`-only (`405` with `Allow: GET` otherwise), any
other path is `404`, and every response carries `Cache-Control: no-store`. An enrolled
device (a name matching the device pattern) is admitted only if it is listed under
`devices` and its leaf, by the fingerprint header, is the newest the hub issued for
it; otherwise it gets `403`, or `503` while the issuer cannot say which leaf is newest.
A KeyChain identity is unaffected. A single filter,
`visibleMachines`, decides what a caller may see: the machines whose
`mesh-t3-<machine>` entry lists the caller. Every `/api/v1` endpoint that lists
machines goes through it, so `/api/v1/fleet` reuses it; `/api/v1/trust` lists none.

`GET /api/v1/machines` returns the visible machines sorted by name:

```json
{"machines":[{"name":"z-arch","online":true,"lastSeen":"2026-11-18T08:00:00Z","viewerUrl":"https://t3.z-arch.mesh.noqer.com","agentIdentity":"agent-z-arch","direct":{"address":"192.168.2.71","port":27443}}]}
```

`online` means a live tunnel session. `lastSeen` is RFC 3339 UTC, the current time
while online and the last disconnect otherwise (as in `/status`), or `null` if the hub
has not seen the machine since it started. `viewerUrl` is
`https://t3.<machine>.<viewerDomain>`. `agentIdentity` is the machine's configured agent
identity, `agent-<machine>`: the one URI an app expects in the certificate of the agent
it connects to directly.

`direct` says where an enrolled device may reach the machine directly on the LAN
([Direct device access](#direct-device-access)): `address` is an IP literal (IPv6 without
brackets or zone) and `port` the agent's device listener port. It is `null` (the key is
always present) unless the machine has a live tunnel session that the hub marks home
(the same verdict as `tunnel.path` being `LAN`) and its agent reports the listener bound.
The agent reports the addresses it is bound on; the hub keeps those inside `homeCIDRs`
(so a wrong or hostile report cannot point a device outside the LAN, and an app still
checks the agent's identity before it sends anything), drops unspecified, multicast and
link-local ones, prefers IPv4 to IPv6, and within the family the address the tunnel
arrived from, else the lowest. It is the newest live session's report, so a reconnect
withdraws a route until the new session reports its listener. A machine that is offline,
away, or whose listener is closed has none.

`GET /api/v1/fleet` returns the same visible machines, sorted by name, with the state
`/status` reports for each, read through the same code:

```json
{"caller":{"path":"LAN"},"machines":[{"name":"z-arch","online":true,"lastSeen":"2026-11-18T08:00:00Z","viewerUrl":"https://t3.z-arch.mesh.noqer.com","agentIdentity":"agent-z-arch","direct":{"address":"192.168.2.71","port":27443},"agentVersion":"0.1.12","certNotAfter":"2027-02-01T00:00:00Z","tunnel":{"path":"LAN","connectedSince":"2026-11-18T06:00:00Z"},"alerts":["cert-expiry"]}]}
```

Each entry is the `/machines` object (so `agentIdentity` and `direct` too) plus `agentVersion` (as the agent reported it,
`null` if unknown), `certNotAfter` (best known leaf expiry, `null` if unknown),
`tunnel` (`path` is `LAN` or `OCI` and `connectedSince` the live session's accept
time, both `null` while not connected) and `alerts`, the sorted names of the
`/status` alerts that are currently true (`cert-expiry`, `disconnected`,
`update-failed`), `[]` when none. `caller.path` is the path of the API request
itself: `LAN` if the `X-Real-IP` header, which Traefik's `traefik-real-ip`
middleware sets at the entrypoint, is inside `homeCIDRs`, `OCI` if it is outside,
`null` if the header is missing or not a bare IP address. The TCP peer is a Traefik
pod and is never used.

`GET /api/v1/trust` returns what an app needs to verify an agent when it connects to
one directly, with the same admission as `/machines` and no per-machine filter:

```json
{"caBundle":"<PEM, one or more clients CA certificates>","caRevision":"<opaque string>","revokedAgents":["<sha256 hex>"]}
```

`caBundle` and `caRevision` are the hub's clients CA bundle and its revision.
`revokedAgents` is the sorted list of blocked leaf fingerprints (lowercase hex SHA-256
of the DER) from the policy, `[]` when none. The hub cannot tell an agent's leaf from
another by its fingerprint, so the list holds every blocked leaf and an app compares an
agent's leaf against it. A disabled agent identity is not in it: block its leaf to
revoke it on devices. A CA rotation reaches an app through the revision.

#### Device renewal

`POST /api/v1/renew` renews an enrolled device's certificate with a new key. The
request is `Content-Type: application/x-pem-file` (parameters such as `charset` are
allowed) with a PEM CSR as the body, at most 16 KiB. It goes through the admission
above and the hub allows 10 seconds to read an admitted renewal's body. The caller must be:

- admitted as for any `/api/v1` endpoint: the three `X-Mtls-Mesh-*` headers, identity
  not disabled, leaf not blocked and not expired, and listed under `api.identities`;
- listed under `devices`: a KeyChain identity such as `z-phone` is a legitimate API
  caller and gets `403` here, whatever it posts and with any method;
- holding the newest leaf the hub issued for its identity (`403` otherwise).

The CSR follows the rules of [Device enrollment](#device-enrollment) (ECDSA P-256,
empty subject, exactly one URI SAN, no DNS, IP or email SAN, no other requested
extension) and must name the caller's own identity. The hub cannot see the old public
key on this path (only the fingerprint header arrives), so it does not check that the
key is new; the app generates a new one. The response is `200` with:

```json
{"certificate":"<PEM leaf>","chain":"<PEM issuer chain>","caBundle":"<PEM>","caRevision":"<opaque string>"}
```

Status codes: `400` for an unusable CSR, `403` for a refused caller or a CSR for another
identity, `405` (`Allow: POST`) for another method, `408` when the body read times out,
`413` over 16 KiB, `415` for another content type, `429` with `Retry-After` when
renewals are limited, `502` when issuance fails (without detail), and `503` when the
newest leaf cannot be checked. Renewals are
limited to 5 attempts per 10 minutes per identity, counting every attempt that passed
admission, and to one at a time. A renewal outlives a client that hangs up: the hub
finishes the issuance and records the new leaf, so a reply the app never read leaves it
with a superseded leaf, and the recovery is re-enrollment with a new token.

#### Newest leaf for devices

The hub admits only the newest issued leaf of an enrolled-device identity on the viewer
hosts and on `/api/v1`, using the fingerprint header, as it does for agent tunnels: it
asks the issuer when its own record disagrees (it keeps none across restarts), and
admits, with a warning, a leaf the issuer has no record of at all, as for agents. A
leaf issued by enrollment or renewal supersedes the previous one at once: the hub closes
the old leaf's open streams and pushes the new fingerprint to every agent. A device that
is no longer listed under `devices` is refused and its streams are closed.

Deploy order: the hub parses its config with unknown fields rejected, so the hub
release that understands `api` ships first and the chart change that renders it comes
after. Rolling the hub back past that release requires reverting the chart first: an
older hub rejects the config, so it fails to start, or keeps its previous config and
raises `/alerts/stale-config`.

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
  devices:                       # listener for enrolled devices (the Android app)
    enabled: true                # default: on whenever direct is
    port: 27443                  # default 27443, bound on the same addresses
```

Link ports are explicit because T3 stores the URL; a port must never move. On each
machine, peers are linked with `t3 environment link http://127.0.0.1:<port>`. Link,
direct and device ports sit below both the Linux (32768–60999) and macOS (49152–65535)
ephemeral ranges, so an outgoing connection can never hold one, and the unprivileged
service user can bind them. `direct.devices.port` may not equal `direct.port` or a link
port, and `direct.devices.enabled: true` without `direct.enabled` is refused. The
device listener also stays off when the agent serves no `t3` service.

Link ports are unauthenticated loopback listeners, so any local process on the
machine can use them; that is accepted on single-user machines. To block DNS
rebinding and cross-site requests from browsers, a link port rejects any request,
plain HTTP or WebSocket upgrade, whose `Host` is not `127.0.0.1:<port>` or
`localhost:<port>`, whose `Origin` is present and not one of those, or whose
`Sec-Fetch-Site` is present and not `same-origin` or `none` (which catches no-cors
GETs that carry no `Origin`). Native T3 clients send neither header and pass. The T3
desktop app's window fetches environments cross-site from its own `t3code://app`
origin, which the app registers and no web page can send; requests from that origin,
and from any origin listed in the agent's optional `linkOrigins`, pass whatever their
`Sec-Fetch-Site`. A T3 link also accepts an originless, cross-site `no-cors` image
GET for a signed `/api/assets/<token>/<filename>` URL. The desktop renderer uses
this request shape for inline images. The link strips cookies and authorization
headers from these requests, and T3 validates the asset token upstream. For
embedded HTML charts, an originless cross-site iframe navigation can load an
inline HTML attachment on that same signed route. The link strips credentials,
rejects redirects, and applies an opaque-origin sandbox to the frame response.
Refused requests are logged with the reason.

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
- **Device leaves:** the hub also pushes the newest leaf fingerprint of each enrolled
  device (`deviceLeaves`, see the wire protocol), and the agent caches it with the rest.
  It holds one fingerprint per device and accepts only that one (`allowDevice`), so a
  renewed or re-enrolled device's old leaf is refused as soon as the update arrives.
  The cache is valid for the same `cacheTTL` as the rules. The device listener
  ([Direct device access](#direct-device-access)) uses this.
  The hub learns each device's newest leaf from its own issuances and, once after it
  starts, from the issuer; when the issuer cannot be asked it sends no list (so an agent
  never loses a leaf to an outage) and asks again after 30 s.
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

### Direct device access

At home an enrolled device (the Android app; the fork's `docs/android-fork.md`, item 5)
can reach a machine's T3 over the LAN without the hub, so a cluster outage does not cut
the phone off. Each agent runs a second listener for it, separate from the
`t3-mesh-direct/1` one: that one carries agents' byte streams, this one speaks HTTP and
proxies to the machine's T3 (`serve.t3`, `127.0.0.1:3773`).

- **Listener.** TLS 1.3 only, ALPN `http/1.1` only (the viewer path reaches T3 as
  HTTP/1.1, and a caller that does not negotiate it is closed), session tickets off. The
  server certificate is the agent's own leaf: it has `server auth` and the one URI
  `urn:noqer:mtls:clients:agent-<machine>`, which the app checks against the cached
  clients CA bundle in place of a host name. A client certificate is required and
  verified against the cached clients CA bundle with `client auth` usage. The port is
  `direct.devices.port`, default 27443. It binds the same addresses as the
  `t3-mesh-direct/1` listener under the same home gate: only while the hub marks the
  machine home, and during a hub outage only within `cacheTTL` of the last hub contact
  and only while the default gateway's MAC matches the one cached in the last
  hub-confirmed home session. It closes with that listener when the gate closes.
  Between accept and admission at most 64 connections are in flight, each under a 5 s
  limit, so a host on the LAN cannot hold the descriptors with half-open handshakes.
- **Admission.** Decided per connection, inside the TLS handshake, so a refused caller
  gets a `bad_certificate` alert and never an HTTP answer. A caller is admitted only if:
  1. its certificate carries exactly one URI SAN and no DNS, IP or email SAN, the URI is
     `urn:noqer:mtls:clients:<name>` with a name of the enrolled-device kind
     (`device-<name>-mesh`), and the certificate is `client auth` only and not a CA. The
     KeyChain identities (`z-phone`, ...) and agents fail here, whatever the rules say;
  2. the identity is not disabled, the leaf is not blocked, and it has not expired;
  3. the machine's rule (`mesh-t3-<machine>` in `libs/mtls-policy`, as pushed to the
     agent) lists the identity;
  4. the leaf's fingerprint is the newest this agent knows for the identity
     (`deviceLeaves`; see [Direct bypass](#direct-bypass)), so a renewed or re-enrolled
     device's old leaf is refused as soon as the update arrives.

  The same checks run again once the handshake is done, before the session is
  registered, and before every request.
- **Origin.** The viewer host stays T3's logical origin. A request is accepted only with
  `Host: t3.<machine>.<viewerDomain>` for this machine (any case, with or without
  `:443`; the hub sends the viewer domain in `HelloAck` and `Update`, and an agent that
  has none yet accepts no host); any other `Host` gets `421`. `Host` is forwarded
  unchanged. The request is rewritten by the same code as the hub's viewer proxy
  (`internal/viewerproxy`): every `X-Mtls-*` header is dropped, `X-Forwarded-Proto` is
  set to `https`, and no `X-Forwarded-For` is added. Because no proxy sits in front of
  this listener, whatever the client sent as `Forwarded`, `X-Forwarded-*` (all of them,
  not only the four Go removes) or `X-Real-Ip` is dropped too; on the hub those come from
  Traefik. WebSocket upgrades are proxied. Like the hub, the agent opens a connection to
  T3 for each request and reuses none, and a failure to reach T3 is a plain `502`
  (`bad gateway`). An unpaired request therefore gets what it gets through the viewer
  host, which the integration test compares status, headers and body for, for HTTP and a
  WebSocket, and with T3 down.
- **Probe.** `GET /.well-known/t3-mesh/direct` (and `HEAD`; any other method is `405`)
  is answered by the agent itself and never proxied. It is subject to the `Host` rule and
  returns `200` with `Cache-Control: no-store`, `Content-Type: application/json` and
  `{"machine":"<name>","identity":"<caller identity name>"}`. It has no side effect, so
  the app uses it to choose a path.
- **Live sessions.** A session is one TLS connection, however many keep-alive requests or
  WebSocket upgrades it carries. Every session is re-checked with the agent's current
  state on every update from the hub, on every network event, and every second, and a
  request on a session that no longer passes is not served. A session that fails is
  closed at once (the TCP connection first, so a stalled peer cannot delay it, and the
  connections to T3 it opened with it) when the identity is disabled, the leaf blocked,
  the device removed from the rule or from the leaves, a newer leaf known, the leaf
  expired, the home gate closed, or the cache window ended. Revocation latency is the
  hub's push, as for agents.
- **Outage.** The cached rules, revocations, device leaves, trust bundle and viewer domain
  let the listener open after a cold start and admit devices for up to `cacheTTL` (1
  week) without the hub; a revocation made during an outage takes effect when the agent
  next reaches the hub. When the window ends the sessions close at once and new
  connections are closed before the handshake; the socket itself is unbound at the next
  reconcile (a network event, or the 30 s backstop).
- **Route.** The agent reports the port and addresses the listener is bound on in `Status`
  (`deviceListener`), and sends a `Status` whenever that changes. The hub lists them for
  the machine as `direct` in the machine list ([Hub API](#hub-api)).
- **Firewall.** The listener needs inbound TCP on its port (27443) from the LAN. On Linux
  the service user binds it without privilege (the port is above 1024), so only a host
  firewall, such as an nftables input chain that drops by default, needs a rule for it,
  next to the one for the direct port (27400). On macOS the application firewall may block
  an inbound connection to a binary whose ad-hoc signature changes on every update, as for
  the direct port; the same check applies to 27443, on z-mac after the first update to
  0.3.0. Nothing outside the LAN can reach it: it binds only addresses inside `homeCIDRs`.

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
  accepts TCP and the running binary has received a `HelloAck` or a ping reply on
  its hub session within the last minute. Otherwise it defers and checks again every 10 minutes, so a stopped T3 or
  an unhealthy hub never puts a release on probation.
- **Downloads:** `zekihan/t3-mesh` is a public repository, so agents fetch release
  assets anonymously; the signature, not the source, provides integrity. The agent
  builds every URL from the version and the compiled-in prefix
  `https://github.com/zekihan/t3-mesh/releases/download/`; the hub sends only a
  version, never a URL. The signing key is an environment-scoped secret available
  only to the release environment; a tag ruleset limits who can push release tags,
  and the workflow refuses a tag whose commit is not an ancestor of `main`.
- **Fleet rollout:** agents follow `release.version` by default. To canary, pin
  one machine with `machines.<name>.release`, let it pass probation, then move
  `release.version` and remove the pin. A pin below the running version requires
  `rollbackAllowed: true` on the pin. The pin defaults this flag to false. The
  previous-protocol rule in [Tunnel admission](#tunnel-admission) still applies.
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
  repoints when the main daemon's heartbeat file is older than 5 minutes. Either way
  the fallback records the abandoned version as a failed release, so the agent does
  not install it again.
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
| `HelloAck` | hub → agent | home status, `Release`, rules, peer table, revocation list, trust bundle, device leaves, viewer domain |
| `Update` | hub → agent | new rules, peer table, revocation list, trust bundle, device leaves or viewer domain after a change; agents re-check live sessions against it |
| `Release` | hub → agent | desired version, rollback allowed, revision; sent in `HelloAck` and again whenever the chart value changes |
| `Ping` / `Pong` | both | liveness, round-trip time |
| `Renew` / `Renewed` | agent → hub / hub → agent | CSR / certificate and chain |
| `Reject` | hub → agent | reason (identity disabled, leaf not newest, unsupported version, other) before closing a session |
| `Status` | agent → hub | recent warnings, direct-session and device-session counts, the device listener's port and bound addresses, running version, last applied `Release`, policy, revocation, trust-bundle and device-leaves revisions, failed update versions and reasons |
| `Enroll` / `Enrolled` | agent or device → hub / hub → agent or device | token + CSR / certificate, chain, clients CA bundle and its revision (ALPN `t3-mesh-enroll/1` only) |

The device leaves are `{"revision":"<opaque>","leaves":[{"identity":"device-z-phone-mesh","fingerprint":"<sha256 hex>"}]}`,
sorted by identity, one entry per configured device the hub has issued a leaf for.
`HelloAck.deviceLeaves` and `Update.deviceLeaves` carry it, and an absent field means
"unchanged" (an older hub, or one that could not ask the issuer, which keeps what the
agent has). An empty list replaces the cached one, and a device that is no longer
configured is absent from the list. `HelloAck.viewerDomain` and `Update.viewerDomain` carry
the domain viewer hosts live under, which the device listener needs for its `Host` rule;
an absent or empty one means "unchanged". `Status.deviceListener` is
`{"port":27443,"addrs":["192.168.2.71"]}` while the agent's device listener is bound and
absent otherwise, and `Status.deviceSessions` counts its open connections. Every addition
to the protocol is an optional JSON field that releases before it ignore, and the protocol
version in the ALPN is unchanged, so agents of the previous release keep working while the
hub is ahead of them and the other way round; the agent cache gains two optional keys (the
device leaves, then the viewer domain) and keeps format version 1.

Data streams start with one header line of JSON, then raw bytes:

- hub → agent: `{"svc":"t3","viewer":"z-phone"}` for viewer traffic, or
  `{"svc":"t3","from":"agent-z-arch"}` for relayed agent traffic;
- agent → hub: `{"to":"t3.devbox"}` for a link connection.

## Homelab changes

| Where | Change |
|---|---|
| `platform/cert-manager` | approver-policy, built-in approver disabled by appending to the existing `extraArgs`, one policy per issuer usable only by cert-manager, hub policy usable only by the hub and a second hub policy for the enumerated device URIs, test that every issuer has a policy |
| `platform/network-baseline` | `t3-mesh` added to the default-deny namespace list |
| `libs/mtls-policy` | kind `agent` with three identities; `mesh-t3-<machine>` entries listing viewers and permitted agents; kind `enrolled device` with the device identities, which only `mesh-*` entries (and `mesh-hub`) may list, and which renders the hub's `devices` list |
| `libs/app` | a kind filter in `templates/_policy.tpl`, so rendered Traefik middlewares drop kind `agent` |
| `zekihan/traefik-mtls-authz` | options to forward the leaf SHA-256 fingerprint and expiry in `X-Mtls-*` headers, under the same name validation and stripping as `forwardIdentityHeader`, with tests; homelab bumps the plugin version |
| `platform/t3-mesh` (new) | hub Deployment, Services, `IngressRouteTCP` for `mesh.noqer.com`, one `IngressRoute` per viewer host with the `mtls-clients` TLS option, the policy middleware (agents excluded) and viewer headers, Let's Encrypt certificate, DNS records, RBAC, NetworkPolicy (ingress 8443/8080 from Traefik, 9090 from Gatus; egress to the API and DNS), ConfigMap, `clients-ca-bundle` ConfigMap, Gatus endpoints; chart tests that every viewer route uses `mtls-clients` and the policy middleware (without it, client-sent `X-Mtls-*` headers would reach the hub) and that no middleware lists an `agent-*` URI |
| `apps/devbox` | removed at the M2 cutover |
| `platform/traefik` | regenerate the backend-ports file for the hub's 8443 and 8080; at the M2 cutover, drop the `192.168.2.71:3773` devbox `lanPeers` entry in the same change |
| `terraform/git` | minisign key published to the `t3-mesh` repo's `release` environment |
| `terraform/technitium` | LAN A and AAAA records for `mesh.noqer.com` and each viewer host, pointing at the Traefik VIPs. A `mesh.noqer.com` zone is authoritative for its whole subtree, so every viewer record lives in it and the zone is created with all of them in one change; a missing record would be NXDOMAIN at home |
| CI | regenerate `gitops_pr.yaml` and `renovate.json` for the new chart |
| direct device access (0.3.0) | no chart change besides `release.version`: the rules already list the device identities in the `mesh-t3-<machine>` entries, and the hub and agents take the rest (viewer domain, home prefixes, device leaves) from the existing config |

## Observability

The cluster has no metrics scraper or vmalert, so the hub evaluates its own alert
conditions and Gatus probes them. Nothing new is added to the cluster for this.

- **`/status`** (JSON) lists, per agent: connected, path (LAN or OCI), open and
  direct sessions, open device sessions, the device listener the live session
  reports (`deviceListener`: port and bound addresses, absent while not bound), stream
  counts, version, certificate expiry, last seen, and the last acknowledged
  `Release`, policy, revocation, trust-bundle and device-leaves revisions. Rotation
  steps that wait for "every agent acknowledged" read it.
- **`/alerts/<name>`** returns 200 when fine and 503 when firing, one Gatus endpoint
  each: `agent-<machine>-disconnected` (more than 10 minutes, 24 hours for z-mac,
  which is often asleep; counted from hub start after a restart),
  `agent-<machine>-cert-expiry` (under 14 days), `agent-<machine>-update-failed`, and
  `stale-config`.
- The hub logs agent events (connect, disconnect, path change, renewal, issued
  fingerprint, update, rollback, reject, rejected peer) to stdout, so they reach
  VictoriaLogs. It logs the same for devices: each token minted with its kind, each
  enrollment and renewal with the enrolled URI and the old and new fingerprints, and each
  refusal on a viewer host or the API with its reason. Every WebSocket upgrade, and every
  stream an enrolled device opens, is logged at info as `Viewer stream` with the identity
  URI (`uri`), the leaf fingerprint, the target and whether it is an upgrade, so a device's
  chat socket and its streams can be told apart in the log. The many plain requests of
  other viewers stay at debug. Each agent logs the same on its device listener: every
admitted connection as `Device session open` and every WebSocket upgrade as
`Device stream`, with the identity name, URI and leaf fingerprint, every refusal as
`Device caller refused` with the reason, and every session it closes as
`Closing device session` with the reason.
- Gatus canaries: `canary-unauthorized` must be refused on every viewer host, and a
  TLS check on `mesh.noqer.com` confirms the hub serves its certificate. A Gatus
  probe cannot speak the tunnel protocol, so rejection of unauthenticated or
  non-agent tunnel connections is covered by the integration test and by M1.

## Security

| Threat | Control |
|---|---|
| Unauthenticated access to a machine | T3 binds to loopback, LAN mode is off, and pre-existing non-mTLS proxies (z-arch's `caddy-t3.service`) are removed. The only routes in are the tunnel (hub-authenticated agent, Traefik-authorized viewer) and the direct listener (mTLS + cached rules). T3 pairing remains. |
| Stolen phone or browser certificate | Reaches T3 login only; still needs T3 pairing. Cannot register as an agent or open a tunnel (tunnel admission accepts configured agent URIs only). Revoke in `libs/mtls-policy`. |
| Stolen enrolled-device key | The key is non-exportable in the Android Keystore. A leaf is refused as soon as it is not the newest, is blocked or its identity is disabled; the hub cuts its open streams, and agents close its direct sessions when the update arrives. It reaches `mesh-*` hosts and, listed in a machine's rule, that machine's device listener only. Re-enrollment needs an operator token. |
| KeyChain identity, agent or other certificate on the device listener | Admission accepts only an enrolled-device identity (exactly one URI of that kind, `client auth` only, no other name), listed in that machine's rule, with the newest leaf the agent knows; a caller that fails gets a TLS alert, no HTTP. `z-phone` and the other KeyChain identities never connect directly, whatever the rules say. |
| Client-forged identity or forwarding headers on the device listener | `X-Mtls-*`, `Forwarded`, every `X-Forwarded-*` and `X-Real-Ip` are dropped before T3 sees the request; `X-Forwarded-Proto` is set to `https`; identity comes only from the certificate. |
| LAN host abusing the device listener before authenticating | TLS 1.3 with a required, CA-verified client certificate, a 5 s setup limit, at most 64 connections between accept and admission, closed without a handshake while the home gate is closed, `Host` held to this machine's viewer host. |
| Wrong or hostile direct route in the machine list | The hub lists only addresses inside `homeCIDRs` that the agent says it is bound on; the app checks the agent's certificate (server auth, the one expected `agent-<machine>` URI, chained to the cached clients CA bundle, not revoked) before it sends T3 credentials, and refuses another peer. |
| KeyChain identity used on the device paths | `z-phone` and the other KeyChain identities are refused by `renew` (devices only), are not in `devices`, and cannot enroll: a token is minted only for a name listed under `devices`. |
| Agent certificate used as a viewer | Traefik middlewares exclude kind `agent`. |
| Local process or web page using a link port | Loopback only, `Host` and `Origin` checks on every request against DNS rebinding and cross-site requests, T3 pairing. Other local users are trusted (single-user machines). |
| Direct listener exposed off the LAN | Binds only addresses inside `homeCIDRs`, and during a hub outage only when the default gateway's MAC matches the cached home gateway. TLS 1.3 only. The device listener binds the same addresses under the same gate. |
| In-cluster spoofing of PROXY v2 or viewer header | NetworkPolicy admits only Traefik on 8443 and 8080. |
| Stolen agent key | Revoke in `libs/mtls-policy`; the hub cuts the tunnel and relayed streams at once; peers close live direct sessions and refuse new ones as soon as they receive the update, and stop all direct traffic at the end of the cache window. The key file is readable only by the service user. |
| Compromised hub | Can mint only the configured agent certificates and the enumerated device certificates (approver-policy, two policies, usable only by the hub's ServiceAccount; a device certificate has no `server auth`). Never `z-phone` or any other identity. The device identities reach only `mesh-*` hosts, which the hub already proxies. Can reach every agent's services, as any relay could. T3 pairing still applies. |
| Spoofed home status | Decided by the hub from the tunnel's source address, not by the agent. Traefik trusts PROXY headers only from frpc. A wrong guess during an outage only causes a failed, identity-checked dial. |
| Malicious update | minisign signature with embedded keys, dual-signed during key rotation, download URL fixed in the binary, no downgrade except a hub-marked rollback to a signed release, automatic rollback. Accepted risk: a compromised hub or chart value can roll every agent back to any older signed release at or above `minStateVersion`, including one with a known flaw. |
| Enrollment abuse | 15-minute single-use token bound to one identity, minted only for the kind it is for, operator access via `kubectl exec`, certificate-less connections only on the enrollment ALPN while a token is outstanding, size and time limits, rate limit, logging. |
| Old agent or device leaf after renewal or re-enrollment | Hub admits only the newest issued leaf per identity (agents on the tunnel, devices on viewer hosts and the API) and closes the old leaf's streams; issued fingerprints are logged; agents are pushed the newest device leaf and accept no other. |
| Renewal abuse | Devices only, newest leaf only, own identity only, one at a time, 5 per 10 minutes per identity, 16 KiB, no CSR extension besides the URI SAN. |
| T3 trusting loopback clients | Every viewer and peer reaches T3 from `127.0.0.1`. The M1/M2 gates prove that an unpaired request through the agent gets nothing a remote unpaired client would not. |

## Rollout

| Milestone | Scope | Done when |
|---|---|---|
| M0 | approver-policy and per-issuer policies, plus the `t3-mesh` namespace, hub ServiceAccount and hub policy (no workload) | the render test passes and every existing certificate renews; a forced renewal of one Let's Encrypt and one clients certificate succeeds; CertificateRequests from the hub ServiceAccount for `urn:noqer:mtls:clients:z-phone`, and for `agent-z-mac` with an added DNS SAN, are denied by the hub policy and get no certificate |
| M1 | `traefik-mtls-authz` extension released and deployed first; then hub, agent, tunnel, token enrollment, live viewer revocation, Gatus canaries and `/status`; z-mac only, with its T3 bound to `127.0.0.1` and LAN mode off before the checks | the phone opens `t3.z-mac.mesh.noqer.com` from mobile data, home and away; a forged PROXY header through the public path, or from a non-frpc pod, does not change the source the hub sees; z-mac at home resolves `mesh.noqer.com` to the LAN VIP and is marked home over both IPv4 and IPv6; an unpaired request through the agent gets nothing a remote unpaired client would not; the macOS risks in [Platform notes](#platform-notes) are checked; blocking the phone's leaf closes its open WebSocket |
| M2 | devbox and z-arch on the mesh, link ports | the M2 gate below passes; then the hard switch below |
| M3 | direct bypass, outage mode, live direct-session revocation | home links stay up with the hub scaled to zero; revoking a peer closes its open direct session; z-mac on a foreign `192.168.x` network with the hub blocked does not listen |
| M4 | CSR renewal, trust bundle, self-update with rollback and launcher fallback, integration test, Gatus alert endpoints | a forced renewal and a deliberately broken release (agent and launcher) both recover on z-mac; the macOS checks pass again after the update |

**M1 rollout (2026-11-17):** hub v0.1.6 and the z-mac agent v0.1.1 are live, with
z-mac's T3 local-only. Proven so far: the viewer path on LAN and public routes with
z-arch's device certificate; forged PROXY headers through the public path and the LAN
VIP never reach the hub as a source, and a non-frpc pod is refused on `websecure-frp`;
z-mac is marked home over IPv4 and IPv6; every `/api/` route answers an unpaired
request through the agent as it answers a remote unpaired client; the LaunchDaemon dials
the LAN VIP despite Local Network privacy (the application firewall is off, and only
matters for M3's direct listener); a live T3 WebSocket through the hub closes 0.8 s
after the hub applies a blocked fingerprint. Revocation latency is bounded by the
kubelet's ConfigMap refresh (about 70 s here). The phone, paired with a token from
`t3 auth pairing create`, used T3 on z-mac from mobile data and from home; blocking
its leaf in the hub's configuration revoked its open stream and refused its reconnects
until the block was removed.

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

**M2 rollout (2026-11-17):** devbox and z-arch run agents (self-updated with z-mac to
v0.1.7), and every machine links to the other two through loopback link ports
(devbox 27301, z-mac 27302, z-arch 27303), each link keeping its relay URL as a
fallback. The loopback-link open item is resolved: T3 identifies the peer through a
link port, and the desktop app's window reaches it once the guard trusts
`t3code://app`. z-arch's and devbox's T3 listen on `127.0.0.1` only (`loopback-browser`
policy); z-arch's `caddy-t3` and devbox's Caddy LAN proxy are disabled. A linked T3
session reconnected after a hub restart and after z-mac slept, and the phone reached
all three machines as a viewer, home and away. The devbox cutover removed
`apps/devbox`, its `lanPeers` entry, the `devbox.noqer.com` public and LAN records, and
the old host policy; the retired Argo CD Application, namespace and AppProject were
deleted by hand because the ApplicationSet does not delete. T3 Connect stays on for
now.

**M3 rollout (2026-11-17):** direct is enabled on all three agents (port 27400), each
binding only its LAN IPv4 and ULA addresses. With the hub scaled to zero, every link
between home machines kept working over direct sessions. Blocking devbox's agent leaf
made z-mac close both of its direct sessions with devbox within 0.1 s of the hub's
update and refuse new ones, while the hub cut devbox's tunnel. On a phone hotspot with
the hub's public addresses blackholed, z-mac opened no direct listener and dialed no
peer; the hotspot's `10.167.57.0/24` is outside `homeCIDRs`, so the gateway-MAC check
for a foreign `192.168.x` network was covered by the integration test rather than on
z-mac. Since v0.1.8 the agent logs each change of its direct decision with the reason.

**M4 rollout (2026-11-17):** a `renew-now` file forced a renewal on z-mac (new leaf
in 2 s, hub admitted it, no leftover files). Two deliberately broken releases, built
from a `FAULT` file and marked as pre-releases, proved recovery on all three
machines: v0.1.10 (`agent-crash`) was rolled back within seconds and recorded as
failed; v0.1.11 (`launcher-crash`) passed probation, then its launcher failed and the
fallback restored v0.1.9 and recorded the version (Linux within 15 s, z-mac after
about 13 minutes through the 5-minute fallback daemon). The hub's update-failed alert
fired for each machine and cleared once v0.1.12 was desired, as Gatus showed. The
rollout found and fixed two bugs: the fallback did not record the abandoned version,
so the agent would have reinstalled it, and the update precondition counted only the
session's `HelloAck`, which deferred every update on a long-lived session. After the
update z-mac still dials the LAN and accepts direct connections; its application
firewall is off, so the ad-hoc-signature firewall risk remains untested.

**Rolling out direct device access (0.3.0).** The hub release ships first (the agents'
`Status.deviceListener` and the `HelloAck` viewer domain are optional fields, so an agent
ahead of its hub is harmless, but the hub must understand them to list a route), then the
homelab chart's `release.version` moves every agent to 0.3.0 through the usual self-update.
Open inbound TCP 27443 from the LAN on each machine's host firewall first, next to 27400,
and on z-mac check the application firewall after the update, as for the direct port. A
machine's device listener opens once it has a hub-confirmed home session on 0.3.0 (its
cache then holds the viewer domain), and the machine list carries its `direct` route
within seconds of that. Rolling back to 0.2.0 removes the listener; the cache's extra key
is ignored, so no `minStateVersion` is needed.

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

The direct device listener has its own tests. Unit tests in `internal/agent/direct` cover
admission (the KeyChain identity, an agent, a device missing from the rule, a superseded
leaf, a device leaf with `server auth` or an extra name or two URIs, another CA, no
certificate, a blocked leaf, a disabled identity, an expired leaf, ALPN and TLS version),
the `Host` rule, header stripping, the probe, WebSocket proxying, a `502` with T3 down,
closing live keep-alive connections and WebSockets on each loss (blocked leaf, disabled
identity, rule removal, a newer leaf, leaf expiry, cache window, left home) and that a
request on a revoked connection is not served, the outage window, the home gate (hub
connected but away, a foreign network matching the home prefixes, no cached gateway, cache
window over), and that the listener binds and unbinds with its notification. The
integration test (`test/integration/device_test.go`) runs a real hub and an agent with the
device listener over loopback and enrolls the device through the enrollment protocol: a
device enrolled and listed is proxied over HTTP and WebSocket and appears as the machine's
`direct` route; the KeyChain identity, an agent, an enrolled device not in the rule and a
superseded leaf are refused; a wrong `Host` is `421`; forged headers are stripped; the
probe answers; a WebSocket closes on a blocked leaf, a rule removal, a new leaf, a disabled
identity, a device dropped from the configuration and leaf expiry; with the hub stopped the
open session and new ones keep working, also after a cold start, and stop at the end of the
cache window; an agent that boots in an outage on a foreign network with a matching home
prefix, or moves to one, opens or keeps no listener; the hub's home verdict opens and
closes the listener and the route; and an unpaired request gets the same status, headers
and body on the direct path as through the viewer host, for HTTP, a WebSocket, and T3 down.

### Compatibility with upstream T3

The tests above run against a stand-in T3. `TestT3Compat` (`test/integration/t3compat_test.go`)
puts a real `t3 serve` behind the same hub and agent, with a temporary data directory and
project, and runs what the web and mobile apps do through three routes: the hub's viewer host
(`t3.<machine>.<viewerDomain>` with the `X-Mtls-Mesh-*` headers), the agent's device listener
(an enrolled device), and T3 directly as the control. It checks that unpaired requests
(`/.well-known/t3/environment`, `/`, the auth endpoints with bad credentials, a WebSocket
upgrade without a valid ticket) get the status, headers and body semantics T3 gives on its
own, so no forwarded `Host`, `Origin` or `X-Forwarded-Proto` is rejected; that a pairing
credential minted with `t3 auth pairing create` redeems for a bearer token (`/oauth/token`)
and for a browser session cookie that is `Secure` behind the proxies; that a WebSocket ticket
opens the RPC socket (`/ws`), which then carries a request, a message over 100 KB, a
subscription stream, four seconds of idle pings and a clean close, with and without an
`Origin`; and that T3's largest static script arrives unaltered. Bodies are compared as
data, so a harmless upstream change does not fail it. A check that fails on a proxied route
but passes on `direct` is the proxy; one that fails on all three means T3 changed and the
test needs updating.

It runs only when `T3_COMPAT_BINARY` names a `t3` executable, so `go test ./...` needs no T3:

```sh
T3_COMPAT_BINARY=$(command -v t3) go test -count=1 -run '^TestT3Compat$' -v ./test/integration
```

`.github/workflows/t3-compat.yaml` runs it daily and on demand against the latest `nightly`
on npm and the nightly the machines run (the `t3mesh-base: v<version>` line in the newest
release of `zekihan/t3code`; only the latest is checked when that cannot be resolved).
`workflow_dispatch` takes `t3_versions` to check others; such a run does not touch the
issue. While either version fails the workflow keeps one open issue, "T3 nightly
compatibility", with the versions, the failing tests and the run's link, and it closes the
issue when the check passes again.

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
| Hub API | `hub.mesh.noqer.com` on the viewer listener, matched before `HostTarget`; callers in `api.identities` (not a rule), same `X-Mtls-Mesh-*` admission, per-caller filter from `mesh-t3-<machine>` |
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
| Fleet rollout | fleet version with optional machine pins; hub accepts current and previous protocol |
| Launcher | vetted by self-test in probation; `previous-good` fallback via systemd `OnFailure` / macOS fallback daemon |
| Direct listener during outage | also requires the cached home gateway MAC; TLS 1.3 only |
| Enrollment surface | own ALPN, only while a token is outstanding, size and time limits |
| Device identities | `device-<name>-mesh`, own namespace, listed under `devices`, `client auth` only, ECDSA P-256, 8760h, second approver-policy for the hub's ServiceAccount |
| Device enrollment | same ALPN and messages as agents; the reply adds the clients CA bundle and revision; `enroll-token --device` |
| Device renewal | `POST /api/v1/renew`, devices only, newest leaf only, limited per identity; a lost reply is recovered by re-enrollment |
| Device leaves | newest leaf per device on viewer hosts and the API, and pushed to agents; `GET /api/v1/trust` for the clients CA and blocked leaves |
| Agent renewal | at 90 days left; hub admits only the newest leaf per identity |
| T3 on machines | loopback-bound, LAN mode off, other non-mTLS proxies removed before the gates |
| Direct device access | second agent listener (`direct.devices`, port 27443, TLS 1.3, ALPN `http/1.1`), separate from `t3-mesh-direct/1`, same home gate and cache window |
| Device listener admission | in the handshake: one device-kind URI, `client auth` only, in the machine's rule, newest leaf the agent knows; refusal is a TLS alert, no HTTP; the KeyChain identities never connect |
| Device listener origin | `Host` must be `t3.<machine>.<viewerDomain>` (domain sent by the hub), else `421`; same rewrite code as the hub's viewer proxy plus dropping every client forwarding header |
| Device listener probe | `GET /.well-known/t3-mesh/direct`, answered by the agent, `{"machine","identity"}` with `no-store` |
| Direct route in the machine list | `direct` (address and port) and `agentIdentity`; non-null only while the hub marks the machine home and the agent reports the listener bound; IPv4 inside `homeCIDRs` preferred, then the tunnel's source address |
| Hub state | none persistent; tokens and last-seen lost on restart |
| Milestones | approver-policy first (M0), then M1–M4 |
| devbox cutover | hard switch |
| Testing | unit tests plus one in-process hub + two agents test |

The hub reports each machine’s effective release as `desiredVersion` in `/status`
and `/api/v1/fleet`. Release revisions are derived from each effective release.

`t3-mesh-hub validate --config config.yaml` runs the hub configuration parser
offline. With `--trust ca.crt` it also validates the clients CA bundle; it does
not read the serving certificate or require network access.
