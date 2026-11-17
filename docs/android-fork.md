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
- Direct LAN connections from the phone. The direct listener trusts only agent
  identities; viewer authorization stays in Traefik and the hub.
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
  does not handle.
- **Certificate renewal.** Device certificates renew yearly. When the stored
  KeyChain alias is missing, the app asks for the identity again.
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
- **Filtering.** The hub returns only the machines whose `mesh-t3-<machine>` entry
  lists the caller, with name, online, last seen and viewer URL.
- **App.** A "Mesh" screen lists the machines. An entry opens or pairs the
  environment at its viewer URL. Pairing itself stays manual: T3 pairing is the
  second lock and the hub never pairs on the user's behalf.

### 5. Fleet status

`GET /api/v1/fleet` on the same host returns agent versions, certificate expiry,
tunnel uptime and alert state from the hub's `/status`. It is a read-only screen.

### 2. Dev-server previews

- **Explicit services.** Each preview port is a declared service per machine, such
  as `mesh-vite-z-arch` with host `vite.z-arch.mesh.noqer.com`, its own certificate,
  DNS record and policy entry. This keeps the design's "no wildcard records or
  certificates" rule.
- **Agent.** The agent's `serve` map gains the matching local ports.
- **App.** A preview tab maps `localhost:<port>` on a machine to its mesh host.
  Upstream is adding on-device localhost tabs (PR #38045), so the fork maps those
  rather than adding its own browser.

### 3. Device enrollment with a Keystore key (last)

- **Key.** The app creates a non-exportable key in the Android Keystore and sends a
  CSR with a one-time token, as agents enroll.
- **Separate identities.** Enrolled devices get a namespace that is distinct from
  the existing device identities, e.g. `urn:noqer:mtls:clients:device-z-phone-mesh`.
  That identity appears only in `mesh-*` policy entries. This way a compromised hub
  that can mint it reaches the mesh viewers, which it already proxies, and nothing
  else. It must never be able to mint `z-phone`, which every app policy trusts.
- **Approver-policy.** The hub's CertificateRequestPolicy gains the enumerated
  device URIs, with no wildcard. Enrollment uses a separate token kind
  (`enroll-token --device`).
- **Renewal.** It follows the agent rules: renew with 90 days left, and the hub
  admits only the newest leaf.

## Build and distribution

- **CI.** A scheduled GitHub Actions job in the fork rebases onto the newest
  nightly, runs the mobile tests, then `expo prebuild` and
  `./gradlew assembleRelease` for `arm64-v8a` only (Galaxy S24 Ultra and Galaxy
  Tab S9 FE+).
- **Signing.** The APK signing key lives in the secrets repo and is published to
  the fork's Actions secrets by homelab `terraform/git`, like the t3-mesh minisign
  key. Losing it means reinstalling and re-pairing, so it is backed up.
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
- `rev` restarts at 1 on each new upstream base.
- The upstream build number only increases, so `versionCode` does too.
- Hub endpoints are versioned (`/api/v1/...`) independently of t3-mesh releases.

## Weekly upkeep

- **Automation.** A scheduled task runs the rebase, tests and build, and publishes
  the release. It reports only conflicts or failures.
- **Normal week.** A clean rebase, then a 10–15 minute phone check: pair, chat,
  reconnect, an attachment and the Mesh screen.
- **Bad week.** Conflicts concentrate in `features/connection` and `app.config.ts`.
  An Expo or React Native upgrade that breaks the native module costs half a day to
  a day every month or two.

## Milestones

| | Scope | Done when |
|---|---|---|
| A0a | Fork, port of the mTLS commit, network-stack audit, app identity; local build installed with `adb` | The phone pairs with z-arch over `t3.z-arch.mesh.noqer.com` using the KeyChain identity, chats, uploads an attachment, opens a file and a PDF preview, and survives a cold start |
| A0b | CI build, signing, GitHub Releases, Obtainium | Both devices install and update the fork through Obtainium from a CI release, and the A0a checks pass on that build |
| A1 | Item 1: `hub.mesh.noqer.com`, `/api/v1/machines` and the Mesh screen | The Mesh screen lists all three machines with online state; a viewer missing from a machine's policy does not see that machine |
| A2 | Item 5: fleet screen | Versions and certificate expiry match `/status` |
| A3 | Item 2: one declared preview service on z-arch | A Vite dev server on z-arch opens from the phone, home and away |
| A4 | Item 3: Keystore enrollment | The phone enrolls with a token, its key is non-exportable, its identity reaches only `mesh-*` hosts, and a forced renewal works |

## Open decisions

- Whether to do item 3 at all, given the approver-policy widening it needs. Decided
  after A2.
