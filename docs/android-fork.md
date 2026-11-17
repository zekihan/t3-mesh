# T3 Code Android fork with mTLS

Status: proposed. Date: 2026-11-17.

A personal fork of the T3 Code mobile app (`pingdotgg/t3code`, `apps/mobile`) that
connects to the mesh viewer hosts with the phone's client certificate, plus a few
mesh features served by the t3-mesh hub. It is built weekly and installed only on
the owner's own devices.

## Goals

- Use the native app, not only the browser, against
  `t3.<machine>.mesh.noqer.com`, with the identity already in the Android KeyChain.
- List the mesh machines in the app without adding each one by hand.
- Keep the weekly upkeep near one hour.

## Non-goals

- Publishing to Play, F-Droid or any other store.
- Direct LAN connections with the KeyChain identity. Viewer authorization for
  that identity stays in Traefik and the hub; only the enrolled identity of item 3
  may connect directly (item 4).
- Push notifications, Clerk sign-in and the managed relay. They depend on
  upstream's cloud accounts, and T3 Connect is off on every machine.

## Background

- **No client certificates upstream.** On Android, the app's HTTP and WebSocket
  traffic go through React Native's OkHttp. Upstream has no client-certificate
  support and no maintainer response to the request (Discussion #17218).
- **Existing implementation.** nickypro's branch `feat/android-client-certificates`
  (one commit, about 2k lines with tests) adds a KeyChain-backed OkHttp socket
  factory through an Expo config plugin and native module,
  `apps/mobile/modules/t3-client-certificates`. It also covers Expo FileSystem
  attachments and Expo Video. On 2026-11-17 it was 3,874 commits behind upstream
  `main` (last rebased 2026-10-30).
- **Upstream baseline.** On 2026-11-17 upstream used Expo 58.0.23 and React Native
  0.88.1. The version comes from `T3CODE_MOBILE_VERSION`, and Expo Updates uses the
  `fingerprint` runtime-version policy.
- **Change rate.** Over 14 days upstream averaged ~213 commits a day, ~32 of them
  in `apps/mobile`. The files the mTLS commit edits saw ~25 commits in total.
- **Servers.** They run upstream nightly builds. Pairing works against the mesh
  hosts: with a one-time token from `t3 auth pairing create --base-url
  https://t3.<machine>.mesh.noqer.com` on z-mac (desktop app, local-only), and the
  normal pairing flow on z-arch and devbox.

## Fork

- **Repository.** A public GitHub fork, `zekihan/t3code`, branch `mesh`. GitHub
  does not allow a private fork of a public repository, and the mesh hostnames are
  already public in the t3-mesh docs. The fork's commits stay a small stack on top
  of an upstream nightly tag.
- **Base.** Every build rebases the stack onto the newest upstream nightly tag,
  e.g. `v0.1.11-nightly.20261117.4838`, not `main`, so the app matches the nightly
  servers. Upstream tags several nightlies a day, and preview tags share the build
  counter; only `-nightly.` tags are bases.
- **First port.** Bring nickypro's commit onto a current nightly. With Expo and
  React Native upgrades in between this is a port, not a cherry-pick; budget
  1–2 days.
- **Network stacks.** nickypro's commit covers OkHttp (fetch and WebSocket), Expo
  FileSystem attachments and Expo Video. The port starts with an audit of every
  other stack that reaches the environment origin: the `react-native-webview`
  surfaces (`WorkspaceFileWebPreview`, `PdfPreview`, `PreviewStreamWebView`,
  `McpAppWebView`, `DeviceStreamWebView`, `HtmlRenderWebView`) and expo-image.
  Android WebView needs `onReceivedClientCertRequest`, which react-native-webview
  does not handle. The audit records a disposition for every surface: supports the
  client certificate, never reaches the environment origin, or disabled in the fork.
- **Per-origin identity.** nickypro's transport stores the alias per exact origin
  and keeps OkHttp from coalescing connections across hosts; the fork keeps both.
  A WebView certificate challenge (including from redirects, frames and
  subresources) is answered only for an origin that already has an alias, and
  cancelled otherwise. T3 credentials stay scoped to their environment.
- **Certificate renewal.** Device certificates renew yearly. When the stored
  KeyChain alias is missing, the app asks for the identity again. When the chosen
  certificate has less than 30 days left (read with `KeyChain.getCertificateChain`),
  the connection screen shows a warning. When an alias is replaced or removed, the
  app evicts pooled OkHttp connections and calls `WebView.clearClientCertPreferences`,
  because WebView caches its certificate decision per host and port.
- **Separate app.** Application ID `com.noqer.t3mesh`, its own URL scheme and app
  name, so it installs next to the official app.
- **Upstream accounts off.** Mostly build settings: `T3CODE_MOBILE_UPDATES_ENABLED=0`,
  `T3CODE_RELAY_URL` unset (Observe then points at `observe.invalid`), no Clerk keys
  and no `T3CODE_ANDROID_GOOGLE_SERVICES_FILE`. The fork's config plugin also removes
  `updates.url`, `extra.eas.projectId`, `owner` and the `app.t3.codes` verified intent
  filter.
- **No over-the-air updates.** An upstream JavaScript bundle must never replace the
  fork's code.

## Mesh features

### 1. Machine list (first)

- **New host.** `hub.mesh.noqer.com` serves `GET /api/v1/machines`. `mesh.noqer.com`
  is TLS passthrough to the agent listener and must stay agent-only.
- **Route.** The host gets its own Traefik `IngressRoute` with the `mtls-clients`
  TLS option and a `mesh-hub` policy entry listing device identities only.
- **API admission.** The hub config's rule map accepts only
  `mesh-<svc>-<machine>` entries, so the `mesh-hub` identities are a separate
  `api.identities` field, never a rule. The hub requires the same `X-Mtls-Mesh-*`
  headers as viewer streams and applies disabled identities and blocked leaves.
- **Filtering.** The hub returns only the machines whose `mesh-t3-<machine>` entry
  lists the caller, with name, online, last seen and viewer URL. Every `/api/v1`
  endpoint applies the same filter.
- **App.** A "Mesh" screen lists the machines. An entry opens or pairs the
  environment at its viewer URL. Pairing itself stays manual: T3 pairing is the
  second lock and the hub never pairs on the user's behalf.
- **One identity for mesh hosts.** The alias chosen for one listed viewer host is
  reused for the other exact `t3.<machine>.mesh.noqer.com` hosts in the machine
  list, so adding a machine shows no certificate picker. Any other host, including
  previews, still shows the picker. Android still asks once per alias, including
  after a renewal.

### 5. Fleet status

`GET /api/v1/fleet` on the same host returns agent versions, certificate expiry,
tunnel uptime and alert state from the hub's `/status`, filtered per machine like
the machine list. It is a read-only screen.

Each environment's connection details show two independent paths and a round-trip
time the app measures itself:

- the machine's tunnel path (LAN or OCI) and state, from the hub's tunnel state;
- the phone's own path, from the source address of that API request as Traefik
  reports it, checked against `homeCIDRs`. The viewer host resolves the same way,
  so this matches the phone's viewer connection.

### 2. Dev-server previews

- **Explicit services.** Each preview port is a declared service per machine, such
  as `mesh-vite-z-arch` with host `vite.z-arch.mesh.noqer.com`, its own certificate,
  DNS record and policy entry. This keeps the design's "no wildcard records or
  certificates" rule.
- **Agent.** The agent's `serve` map gains the matching local ports.
- **App.** A preview tab maps `localhost:<port>` on a machine to its mesh host.
  Upstream is adding on-device localhost tabs (PR #38045), so the fork maps those
  rather than adding its own browser.
- **Isolation.** The preview WebView gets neither the T3 bearer token nor any
  native bridge meant for another surface.
- **HMR.** The dev server's HMR WebSocket must use the mesh host
  (`server.hmr.clientPort: 443` and the host for Vite), or the page loads and live
  reload silently fails.

### 3. Device enrollment with a Keystore key (last)

- **Key.** The app creates a non-exportable key in the Android Keystore and sends a
  CSR with a one-time token, as agents enroll.
- **Separate identities.** Enrolled devices get a namespace that is distinct from
  the existing device identities, e.g. `urn:noqer:mtls:clients:device-z-phone-mesh`.
  That identity appears only in `mesh-*` policy entries. This way a compromised hub
  that can mint it reaches the mesh viewers, which it already proxies, and nothing
  else. It must never be able to mint `z-phone`, which every app policy trusts.
- **Approver-policy.** A second CertificateRequestPolicy for the hub's
  ServiceAccount allows only the enumerated device URIs (no wildcard), usages
  `client auth` and `digital signature` (no `server auth`), ECDSA P-256 and 8760h.
  The agent policy stays unchanged. approver-policy approves a request only when
  one policy allows all of it, so a request mixing agent and device URIs is denied
  by both. The same ServiceAccount is used: a second one in the same pod would be
  equally available to a compromised hub. The hub still enforces exactly one URI.
  Enrollment uses a separate token kind (`enroll-token --device`).
- **Homelab.** `libs/mtls-policy` gains a kind for enrolled devices. A chart test
  fails when any entry other than `mesh-*` lists one.
- **Renewal.** It follows the agent rules: renew with 90 days left, and the hub
  admits only the newest leaf.

### 4. Direct connection at home (after item 3)

At home the phone already stays on the LAN (Technitium answers the viewer hosts
with the Traefik VIP), but every request still crosses the cluster, so a cluster
outage cuts the phone off. This item lets an enrolled device reach a home machine
directly.

- **Admission.** The client certificate must carry exactly one URI, of the
  enrolled-device kind, listed in that machine's `mesh-t3-<machine>` entry, not
  disabled or blocked, and its fingerprint must be the newest issued leaf for that
  identity. The hub sends the accepted leaf fingerprints with the rules, so a leaf
  superseded by renewal is refused. The KeyChain identity never connects directly.
- **Agent listener.** A new TLS 1.3 mTLS HTTP and WebSocket listener per agent,
  proxying to `127.0.0.1:3773`. It binds under the same home gate as the direct
  listener: only while the hub marks the machine home, and during a hub outage
  only while the cached home gateway MAC matches. It strips client-sent `X-Mtls-*`
  headers and sends `X-Forwarded-Proto: https`.
- **Live sessions.** Open HTTP and WebSocket sessions close at once on revocation,
  rule removal, a superseded leaf, leaf expiry, or the end of the cache window.
- **Outage.** Cached rules and fingerprints allow direct device access for up to
  1 week without the hub, the same `cacheTTL` as between machines. A revocation
  made during an outage takes effect when the agent next reaches the hub.
- **Server trust.** Before sending T3 credentials, the app checks the agent's
  certificate against the clients CA from enrollment: `server auth` usage, exactly
  one URI equal to the expected `agent-<machine>`, and not in the cached revocation
  list. No hostname check.
- **Route.** The machine list carries each machine's LAN address while it is home.
  The app persists the direct address and expected agent identity for up to 1 week,
  so a cold start works without the hub. It tries the direct address with a 2 s
  deadline for TCP and TLS, then falls back to the viewer host; a certificate or
  authorization failure on the direct path is shown even when the fallback works.
  The environment's T3 credentials are sent only to its direct address and its
  viewer host. This touches upstream's connection code, the main source of rebase
  conflicts.

## Build and distribution

- **Build job.** A scheduled GitHub Actions job in the fork rebases onto the
  newest nightly, runs the mobile tests, then `expo prebuild` and
  `./gradlew assembleRelease` for `arm64-v8a` only (Galaxy S24 Ultra and Galaxy
  Tab S9 FE+), unsigned. It has no secrets and a read-only token, because it runs
  freshly fetched upstream and dependency code.
- **Sign job.** A separate job in a `release` environment downloads the unsigned
  APK and runs only `apksigner` from pinned build tools. It checks the signed APK:
  application ID `com.noqer.t3mesh`, the expected signing certificate fingerprint,
  `versionName` and `versionCode`, and Expo Updates disabled in the manifest. It
  refuses a `versionCode` at or below the last published one.
- **Publish job.** Only this job may write releases.
- **Signing key.** It lives in the secrets repo and is published to the fork's
  `release` environment by homelab `terraform/git`, like the t3-mesh minisign key.
  Losing it means reinstalling and re-pairing, so it is backed up.
- **Accepted risk.** Releases publish without review. A compromised upstream or
  dependency change reaches both devices, signed, within a week.
- **Distribution.** Each build is a GitHub Release on the fork with the signed APK.
  Obtainium on each device tracks those releases and installs updates; Android
  refuses an update signed with a different key. No index, index key or hosting.
  The APK contains no secrets, but anyone can read the mesh hostnames from it.
- **Sideload check.** Before A0b, confirm that Google's developer verification does
  not block Obtainium installs on the devices. `adb install -r` is the fallback.

## Versioning

| Field | Format | Example |
|---|---|---|
| `versionName` | `<nightly>+mesh.<rev>` | `0.1.11-nightly.20261117.4838+mesh.1` |
| `versionCode` | `<nightly build number> × 100 + <rev>` | `483801` |
| Git tag | `v<nightly>-mesh.<rev>` | `v0.1.11-nightly.20261117.4838-mesh.1` |

- Expo's `version` stays upstream's mobile version (e.g. `2.3.0`), because the app
  sends it to the server in its auth client metadata. The fork's config plugin sets
  `versionName` and `versionCode`; upstream takes `versionCode` from EAS, so a local
  Gradle build would otherwise get 1.
- `rev` restarts at 1 on each new upstream base and stays between 1 and 99.
- The upstream build number only increases, so `versionCode` does too.
- Hub endpoints are versioned (`/api/v1/...`) independently of t3-mesh releases.

## Weekly upkeep

- **Automation.** A scheduled task runs the rebase, tests and build, and publishes
  the release. It reports only conflicts or failures.
- **Normal week.** A clean rebase, then a 10–15 minute phone check against all
  three machines on their deployed server versions: pair, chat, reconnect, an
  attachment and the Mesh screen.
- **Bad week.** Conflicts concentrate in `features/connection` and `app.config.ts`.
  An Expo or React Native upgrade that breaks the native module costs half a day to
  a day every month or two.

## Milestones

| | Scope | Done when |
|---|---|---|
| A0a | Fork, port of the mTLS commit, network-stack audit, per-origin identity, app identity, expiry warning; local build installed with `adb` | Every audited surface has a disposition, and each supported one works against z-arch over `t3.z-arch.mesh.noqer.com` with the KeyChain identity: pair, chat, reconnect, attachment upload and download, video and thumbnails, and each WebView surface; the app survives a cold start; a challenge from an origin without an alias is cancelled; replacing the alias while the app runs takes effect without a restart; a short-lived test certificate shows the warning |
| A0b | Isolated build, sign and publish jobs, GitHub Releases, Obtainium | Both devices install and update the fork through Obtainium from a CI release, the sign job's APK checks pass, and the A0a checks pass on that build on both devices |
| A1 | Item 1: `hub.mesh.noqer.com`, `/api/v1/machines`, the Mesh screen and one identity for mesh hosts | The Mesh screen lists all three machines with online state; a viewer missing from one machine's policy does not see it in any `/api/v1` endpoint; a forged `X-Mtls-*` header and a blocked leaf are refused; a second listed machine is added without a picker, and an unlisted mesh host still shows it |
| A2 | Item 5: fleet screen and connection details | Versions and certificate expiry match `/status` for the machines the caller may see; on mobile data the phone shows OCI while z-mac's tunnel at home shows LAN, and both show LAN with the phone at home |
| A3 | Item 2: one declared preview service on z-arch | A Vite dev server on z-arch loads with its assets and live reload over HMR, home and away; the preview WebView receives no T3 token and no foreign native bridge |
| A4 | Item 3: Keystore enrollment | The phone enrolls with a token, its key is non-exportable, its identity reaches only `mesh-*` hosts, and a forced renewal works; requests from the hub ServiceAccount are denied for `z-phone`, for agent and device URIs together, for a device with `server auth`, with an extra DNS SAN, and with `isCA` |
| A5 | Item 4: direct connection at home | With the hub scaled to zero, the phone at home chats with z-arch directly, also after a cold start; away it uses the viewer host; a stalled direct handshake falls back within the deadline; blocking the enrolled leaf, removing the device from the rule, and a superseded leaf each close or refuse the direct session; an enrolled device not in the rule and the KeyChain identity are refused; an agent on a foreign network matching `homeCIDRs` during a hub outage does not open the listener (integration test, as in M3) |

## Open decisions

- Whether to do item 3 at all, given the approver-policy widening it needs. Decided
  after A2. Item 4 depends on it.
- Whether to do item 4, depending on how often the cluster is down while home.
