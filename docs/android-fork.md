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

- **Repository.** A public GitHub fork, `zekihan/t3code`. GitHub does not allow a
  private fork of a public repository, and the mesh hostnames are already public in
  the t3-mesh docs.
- **Branches.** `main`, the default branch, holds only the fork's workflows and is
  protected. `candidate` receives each rebased stack; `mesh` is moved to a
  candidate only when its release publishes. The app's commits stay a small stack
  on top of an upstream nightly tag.
- **Upstream workflows.** A fork commit deletes upstream's `.github/workflows`, so
  pushing `candidate` runs nothing from upstream. The rebase resolves upstream edits
  to those files by deleting them again.
- **Stack layout.** Fork code lives in its own files: `modules/t3-client-certificates`,
  `src/features/mesh` and `plugins/withMesh*.cjs`. Upstream files get only small
  hook edits that call into them. One commit per concern: mTLS, app identity, CI,
  then one per mesh feature.
- **Base.** Every build rebases the stack onto the newest upstream nightly tag at
  run time, e.g. `v0.1.11-nightly.20261117.4838`, not `main`, so the app matches
  the nightly servers. Upstream tags several nightlies a day, and preview tags share
  the build counter; only `-nightly.` tags are bases. The weekly phone check against
  the deployed servers catches incompatibilities.
- **Upstream.** The client-certificate support stays in the fork. Discussion #17218
  got no maintainer response and PR #27889 was closed; no upstream PR is planned.
- **First port.** Bring nickypro's commit onto a current nightly. With Expo and
  React Native upgrades in between this is a port, not a cherry-pick; budget
  1–2 days.
- **Network stacks.** nickypro's commit covers OkHttp (fetch and WebSocket), Expo
  FileSystem attachments and Expo Video. The port starts with an inventory of every
  feature that fetches from the environment: which fetcher it uses, how redirects,
  credentials and caching behave, and whether the client certificate reaches it.
  It covers the Android PDF preparation path (`preparePdfPreview`), image loading,
  video thumbnails and every `react-native-webview` surface, and records a
  disposition for each: supports the client certificate, never reaches the
  environment, or disabled in the fork.
- **WebViews.** Android caches a WebView's certificate decision per host and port
  for the whole WebView data directory, so an allowlist in
  `onReceivedClientCertRequest` cannot keep one surface from using another's
  decision. At the pinned nightly six surfaces render local or inline content
  (source view, MCP apps through the native bridge, the natively downloaded PDF,
  and file and HTML previews, which A0a confirms load a downloaded file). In the
  main process every WebView cancels certificate requests.
- **Stream process.** The device stream and the browser preview stream run a script
  inside the WebView that connects to the T3 server. They move into a native
  Activity in a separate `:stream` process with its own WebView data directory
  (`WebView.setDataDirectorySuffix`), with commands and messages bridged to the app
  through a bound service. That process answers a certificate request only for the
  environment's exact origin, with its alias, and cancels all others. Changing the
  alias kills the process. This is the largest rebase surface in A0a.
- **Per-origin identity.** nickypro's transport stores the alias per exact origin
  and keeps OkHttp from coalescing connections across hosts; the fork keeps both.
  T3 credentials stay scoped to their environment.
- **Certificate renewal.** Device certificates renew yearly. When the stored
  KeyChain alias is missing, the app asks for the identity again. When the chosen
  certificate has less than 30 days left (read with `KeyChain.getCertificateChain`),
  the connection screen shows a warning. When an alias is replaced or removed, the
  app keeps nickypro's closing of active sockets and cancelling of transfers, evicts
  pooled OkHttp connections, and restarts the stream process.
- **Local network permission.** Android 17 requires a runtime local-network
  permission for apps targeting SDK 37 or newer, which covers the Traefik VIP at
  home and item 4. A0a checks upstream's `targetSdkVersion`; a bump to 37 is
  treated as a breaking change and tested on both devices before publishing.
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
- **Route.** The host gets its own Traefik `IngressRoute` on the viewer routes'
  entrypoints, with the `mtls-clients` TLS option, the `traefik-mtls-authz`
  middleware and a `mesh-hub` policy entry listing device identities only. It also
  needs its own certificate, a public DNS record and LAN A and AAAA records in the
  Technitium `mesh.noqer.com` zone (`terraform/technitium/mesh_dns.tf`); without the
  LAN record the host is NXDOMAIN at home. The chart test that every viewer route
  carries the authz middleware covers this route.
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
- **One identity for mesh hosts.** Opening the Mesh screen the first time asks
  for the identity for `hub.mesh.noqer.com`. That alias is then reused for the
  machines' viewer hosts, but only for URLs exactly equal to
  `https://t3.<machine>.mesh.noqer.com` for a listed machine; any other URL the hub
  returns is ignored. Any other host, including previews, still shows the picker.
  Android still asks once per alias, including after a renewal.

### 5. Fleet status

`GET /api/v1/fleet` on the same host returns agent versions, certificate expiry,
tunnel uptime and alert state from the hub's `/status`, filtered per machine like
the machine list. It is a read-only screen.

Each environment's connection details show two independent paths and a round-trip
time:

- the machine's tunnel path (LAN or OCI) and state, from the hub's tunnel state;
- the phone's hub-request path, from the source address of that API request as
  Traefik reports it, checked against `homeCIDRs`. It is labelled as the path of
  the hub request: split DNS, a network change or a pooled connection can put the
  viewer WebSocket on a different path;
- the round-trip time of that same API request.

### 2. Dev-server previews

- **Explicit services.** Each preview port is a declared service per machine, such
  as `mesh-vite-z-arch` with host `vite.z-arch.mesh.noqer.com`, its own certificate,
  public DNS record, LAN records in the Technitium `mesh.noqer.com` zone, route and
  policy entry. This keeps the design's "no wildcard records or certificates" rule.
- **Agent.** The agent's `serve` map gains the matching local ports.
- **App.** A preview tab maps `localhost:<port>` on a machine to its mesh host.
  Upstream is adding on-device localhost tabs (PR #38045), so the fork maps those
  rather than adding its own browser.
- **Isolation.** The preview WebView gets neither the T3 bearer token nor any
  native bridge meant for another surface.
- **Dev server.** The hub preserves `Host` and terminates TLS before the local HTTP
  hop, so Vite needs the mesh host in `server.allowedHosts` and HMR set to
  `protocol: "wss"`, the mesh host and `clientPort: 443`. Otherwise Vite rejects the
  host, or the page loads and live reload silently fails.

### 3. Device enrollment with a Keystore key (last)

- **Key.** The app creates a non-exportable key in the Android Keystore and sends a
  CSR with a one-time token, as agents enroll.
- **Bootstrap.** Enrollment uses the existing `t3-mesh-enroll/1` ALPN on
  `mesh.noqer.com`, the only path open to a client without a certificate. The app
  verifies the hub's Let's Encrypt certificate with system roots and the exact
  hostname. `enroll-token --device` creates a token kind that only device
  identities accept; the hub checks that the token's kind matches the identity
  kind. The reply carries the leaf, chain and the clients CA bundle with its
  revision.
- **Separate identities.** Each device gets its own identity in a namespace distinct
  from the existing device identities: `device-z-phone-mesh` and
  `device-z-tablet-mesh`, so one device's renewal never supersedes the other's.
  They appear only in `mesh-*` policy entries. This way a compromised hub that can
  mint them reaches the mesh viewers, which it already proxies, and nothing else. It
  must never be able to mint `z-phone`, which every app policy trusts.
- **Use.** Once enrolled, the app uses the enrolled identity for every mesh host:
  viewer hosts, `hub.mesh.noqer.com` and direct access. The KeyChain identity is no
  longer sent to mesh hosts.
- **Approver-policy.** A second CertificateRequestPolicy for the hub's
  ServiceAccount allows only the enumerated device URIs (no wildcard), usages
  `client auth` and `digital signature` (no `server auth`), ECDSA P-256 and 8760h,
  selecting the same clients Issuer and namespace as the agent policy. The hub's
  issuer requests usages by kind; today it always asks for `server auth`, which this
  policy would deny.
  The agent policy stays unchanged. approver-policy approves a request only when
  one policy allows all of it, so a request mixing agent and device URIs is denied
  by both. The same ServiceAccount is used: a second one in the same pod would be
  equally available to a compromised hub. The hub still enforces exactly one URI.
- **Homelab.** `libs/mtls-policy` gains a kind for enrolled devices. A chart test
  fails when any entry other than `mesh-*` lists one.
- **Renewal.** The app renews with 90 days left through `hub.mesh.noqer.com`,
  authenticated by its current leaf, with a new key.
- **Newest leaf.** The hub admits only the newest issued leaf of an enrolled
  identity on viewer hosts and the API, using the fingerprint header, and sends the
  accepted fingerprints to agents for item 4. As with agents, a renewal whose reply
  is lost leaves the device with a superseded leaf; the recovery is re-enrollment
  with a new token. An agent that has not yet received the new fingerprint refuses
  the renewed device on the direct path until it reaches the hub.

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
  only while the cached home gateway MAC matches.
- **Origin.** The viewer host stays T3's logical origin. The listener accepts only
  `Host: t3.<machine>.mesh.noqer.com` for its own machine and forwards it
  unchanged, like the hub's viewer proxy. It strips client-sent `X-Mtls-*`,
  `Forwarded` and `X-Forwarded-*` headers and sets `X-Forwarded-Proto: https`.
  Unpaired HTTP and WebSocket requests must get exactly what they get through the
  viewer host.
- **Live sessions.** Open HTTP keep-alive connections and WebSockets close at once
  on revocation, rule removal, a superseded leaf, leaf expiry, or the end of the
  cache window.
- **Outage.** Cached rules and fingerprints allow direct device access for up to
  1 week without the hub, the same `cacheTTL` as between machines. A revocation
  made during an outage takes effect when the agent next reaches the hub.
- **Server trust.** Before sending T3 credentials, the app checks the agent's
  certificate against the cached clients CA bundle: `server auth` usage, exactly
  one URI equal to the expected `agent-<machine>`, and its leaf not in the cached
  revocation list. No hostname check.
- **Trust refresh.** `GET /api/v1/trust` on `hub.mesh.noqer.com` returns the CA
  bundle with its revision and the agent revocations. The app refreshes it on every
  hub contact and persists it; after 1 week without a refresh the direct path is
  off. A CA rotation therefore reaches the phone like it reaches agents.
- **Route.** The machine list carries each machine's LAN address while it is home.
  The app persists the direct address and expected agent identity for up to 1 week,
  so a cold start works without the hub. The environment keeps its single viewer
  URL: for the direct attempt, the app's OkHttp `Dns` resolves the viewer host to
  the LAN address and the agent check above replaces hostname verification, so
  `Host`, `Origin` and T3 credentials are unchanged. The attempt has a 2 s deadline
  for TCP and TLS and 5 s for the first response byte, then falls back to the
  viewer host; a certificate or authorization failure on the direct path is shown
  even when the fallback works. This touches upstream's connection code, the main
  source of rebase conflicts.

## Build and distribution

- **Workflow source.** Every workflow runs from its definition on the protected
  `main`. The `release` environment allows deployments only from `main`, so nothing
  on `candidate` or `mesh` can reach the signing key. The repository's default
  `GITHUB_TOKEN` is read-only. A0b tests that a workflow added on `candidate`
  cannot read the key.
- **Build workflow.** Dispatched on `main` with a `candidate` commit. It checks out
  that commit, runs the mobile tests (JavaScript and the module's Kotlin unit
  tests; no emulator test, because installing a KeyChain identity needs the UI),
  then `expo prebuild` and `./gradlew assembleRelease` for `arm64-v8a` only (Galaxy
  S24 Ultra and Galaxy Tab S9 FE+), unsigned. It has no secrets, because it runs
  freshly fetched upstream and dependency code. It records the toolchain versions
  (Node, JDK, Gradle, Android build tools) with the artifact.
- **Release workflow.** Triggered by `workflow_run` on a successful build. It
  checks that the run is the fork's build workflow on `main`, succeeded, and built
  the commit `candidate` still points at; a stale run is dropped. It runs in the
  `release` environment under one `release` concurrency group shared with rollback,
  so version assignment and publishing are serialized. It signs with `apksigner`
  from pinned build tools and checks the signed APK: application ID
  `com.noqer.t3mesh`, the expected signing certificate fingerprint, `versionName`,
  `versionCode`, the intent filters, and Expo Updates disabled in the manifest. It
  refuses a `versionCode` at or below the last published one, then publishes the
  release and moves `mesh` to the commit.
- **Rollback.** A manual `workflow_dispatch` on `main` takes the last good release
  tag, rebuilds that commit with the toolchain recorded for it and the next
  `versionCode`, adds a `.rollback` suffix to `versionName`, and publishes it under
  the same concurrency group. Android and Obtainium install only a higher
  `versionCode`, so republishing the old APK would not work. Release tags keep old
  commits reachable after force-pushes. A rollback can meet app state migrated by
  the bad release; A0b tests an update, a rollback and a forward update over a
  paired installation on both devices.
- **Signing key.** It lives in the secrets repo and is published to the fork's
  `release` environment by homelab `terraform/git`, like the t3-mesh minisign key.
  Losing it means reinstalling and re-pairing, so it is backed up.
- **Accepted risk.** Clean rebases publish without review. A compromised upstream
  or dependency change reaches both devices, signed, within a week.
- **Distribution.** Each build is a GitHub Release on the fork with the signed APK.
  Obtainium on each device tracks those releases and installs updates; Android
  refuses an update signed with a different key. No index, index key or hosting.
  Obtainium is configured so that a newer release is offered even when its
  `versionName` names an older nightly, as a rollback does.
  The APK contains no secrets, but anyone can read the mesh hostnames from it.
- **Sideload check.** Before A0b, confirm that Google's developer verification does
  not block Obtainium installs on the devices. `adb install -r` is the fallback.

## Versioning

| Field | Format | Example |
|---|---|---|
| `versionName` | `<nightly>+mesh.<rev>` | `0.1.11-nightly.20261117.4838+mesh.1` |
| `versionCode` | `max(<nightly build number> × 100 + <rev>, <last published> + 1)` | `483801` |
| Git tag | `v<nightly>-mesh.<rev>` | `v0.1.11-nightly.20261117.4838-mesh.1` |

- Expo's `version` stays upstream's mobile version (e.g. `2.3.0`), because the app
  sends it to the server in its auth client metadata. The fork's config plugin sets
  `versionName` and `versionCode`; upstream takes `versionCode` from EAS, so a local
  Gradle build would otherwise get 1.
- `rev` restarts at 1 on each new upstream base and stays between 1 and 99.
- The upstream build number only increases, so `versionCode` normally follows the
  formula; the `max` matters only after a rollback, whose old base would otherwise
  get a lower code. A rollback's `versionName` is e.g.
  `0.1.11-nightly.20261117.4825+mesh.3.rollback`.
- Hub endpoints are versioned (`/api/v1/...`) independently of t3-mesh releases.

## Weekly upkeep

- **Automation.** A weekly T3 scheduled task on devbox fetches upstream and rebases
  `mesh` onto the newest nightly. A clean rebase is force-pushed to `candidate` with
  devbox's existing SSH key, and the task dispatches the build workflow; CI tests,
  builds, signs and publishes it. The clean path runs no upstream code on devbox.
- **Conflicts and failures.** A rebase conflict or a failed build goes to the
  task's agent. It works on a branch from the failed `candidate`, or, for a
  conflict, from the new nightly with the stack applied so far, runs the tests and
  opens a PR into `candidate`. The PR must keep the stack as separate commits, not
  a merge. Nothing publishes until the owner merges, and `mesh` and the previous
  release stay where they were.
- **Reporting.** Details stay in the task's T3 thread; the PR or a failure issue on
  the fork arrives through GitHub notifications.
- **Accepted risk.** devbox's SSH key can push to every repository, and the agent
  runs upstream install and test scripts on devbox when fixing a failure. A
  compromised upstream change met during a fix could use that key.
- **Normal week.** A clean rebase, then a 10–15 minute phone check against all
  three machines on their deployed server versions: pair, chat, reconnect, an
  attachment and the Mesh screen.
- **Bad week.** Conflicts concentrate in `features/connection` and `app.config.ts`.
  An Expo or React Native upgrade that breaks the native module costs half a day to
  a day every month or two.
- **Exit.** No fixed rule; whether to keep the fork is decided case by case. The
  browser on the mesh hosts remains the fallback.

## Milestones

| | Scope | Done when |
|---|---|---|
| A0a | Fork, port of the mTLS commit, network inventory, WebView rule and stream process, per-origin identity, app identity, expiry warning; local build installed with `adb` | Every inventoried feature has a disposition, and each supported one works against z-arch over `t3.z-arch.mesh.noqer.com` with the KeyChain identity: pair, chat, reconnect, attachment upload and download, PDF preparation, images, video and thumbnails, each WebView surface, and the device and browser preview streams; the app survives a cold start; a main-process WebView loading a viewer host gets no certificate, also after a stream has used it; replacing the alias while a WebSocket and a stream are open moves both to the new identity without an app restart; a short-lived test certificate shows the warning |
| A0b | `main` workflows, build and release workflows, GitHub Releases, Obtainium | Both devices install the fork through Obtainium from a CI release and update over a paired installation; update, rollback and forward update work on both; the release checks pass; a workflow added on `candidate` cannot read the signing key; the A0a checks pass on that build on both devices |
| A1 | Item 1: `hub.mesh.noqer.com`, `/api/v1/machines`, the Mesh screen and one identity for mesh hosts | A fresh install opens the Mesh screen before any pairing, at home and on mobile data, and lists all three machines with online state; a viewer missing from one machine's policy does not see it in any `/api/v1` endpoint; a valid but unauthorized client with forged `X-Mtls-*` headers and a blocked leaf are refused; a second listed machine is added without a picker, and an unlisted mesh host still shows it |
| A2 | Item 5: fleet screen and connection details | Versions, certificate expiry, tunnel uptime and alert state match `/status` for the machines the caller may see; on mobile data the hub-request path shows OCI while z-mac's tunnel at home shows LAN, both show LAN with the phone at home, and a network change updates the path; the round-trip time is shown |
| A3 | Item 2: one declared preview service on z-arch | A Vite dev server on z-arch loads with its assets and live reload over HMR from the mesh host, home and away; an undeclared service is refused; the preview WebView receives no T3 token, no client certificate and no foreign native bridge |
| A4 | Item 3: Keystore enrollment | Both devices enroll with tokens under the deployed policy, their keys are non-exportable, their identities reach only `mesh-*` hosts and replace the KeyChain identity there, and a forced renewal works; a wrong-kind token, a replayed token and a disabled identity are refused; a superseded leaf is refused on viewer hosts and the API; requests from the hub ServiceAccount are denied for `z-phone`, for agent and device URIs together, for a device with `server auth`, with an extra DNS SAN, and with `isCA` |
| A5 | Item 4: direct connection at home | With the hub scaled to zero, the phone at home chats with z-arch directly, also after a cold start; away it uses the viewer host; a stalled TLS handshake and a peer that completes TLS but never answers both fall back within the deadlines; unpaired HTTP and WebSocket requests on the direct path match the viewer host; blocking the enrolled leaf, removing the device from the rule, a superseded leaf, leaf expiry and cache expiry each close an open WebSocket or refuse the session; an enrolled device not in the rule, the KeyChain identity and a wrong `Host` are refused; the app refuses an agent with the wrong identity or a blocked leaf; a CA rotation reaches the phone; an agent on a foreign network matching `homeCIDRs` during a hub outage does not open the listener (integration test, as in M3) |

## Open decisions

- Whether to do item 3 at all, given the approver-policy widening it needs. Decided
  after A2. Item 4 depends on it.
- Whether to do item 4, depending on how often the cluster is down while home.
