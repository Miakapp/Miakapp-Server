# Miakapp Server

Miakapp Server is the in-memory Go relay for the Miakapp 3.5 protocol. It
connects home coordinators, authenticated users, and future CLI sessions without
persisting Firebase credentials, Home Keys, push credentials, or product
business logic.

The standalone binary validates short-lived coordinator, CLI, and browser-user
access tokens against the configured control-plane JWKS. Firebase Auth and App
Check credentials remain on the browser-to-control-plane HTTPS boundary and are
never relay credentials. The relay holds no verification secret and never calls
the platform with authenticated authority. It remains an implementation preview
until the staging relay integration gate has passed; do not deploy it as a
production replacement yet.

## Contract

The wire contract is owned by Miakapp-V3
[`RFC 0001`](https://github.com/Miakapp/Miakapp-V3/blob/b927789691dd8cdebc91b673853cdc6711fe057d/docs/rfcs/0001-wire-protocol.md),
and this module pins the canonical Go codec at that immutable commit. Relay
credential profiles are owned by
[`RFC 0004`](https://github.com/Miakapp/Miakapp-V3/blob/cc3bcd70fdb4b058f990ca2607693a2043faebaf/docs/rfcs/0004-platform-control-plane.md),
with the independent Go verifier pinned at that second commit. This repository
does not copy either contract.

The implemented vertical slice includes:

- `/ws` with the `miakapp` subprotocol, exact browser-origin allowlisting,
  binary-only messages, bounded HELLO, and RFC 6455 Ping/Pong liveness;
- injected authentication and immutable principal binding, including
  reauthentication on the existing session;
- per-home process epochs, coordinator generations, presence, and disconnect
  grace;
- atomic five-slice coordinator declarations with locked final revalidation,
  ownership collision rollback, and no partially visible authorization state;
- filtered state dictionaries and snapshots, revisioned patches, atomic state
  mutations, and explicit resynchronization;
- event declarations, ACLs, subscriptions, routing, and relay-created principal
  metadata;
- call routing with connection-local ID rewriting, acceptance, stream credit,
  cancellation, deadlines, terminal results, and conservative
  `OUTCOME_UNKNOWN` handling;
- byte-bounded outbound queues and stable protocol errors; and
- finite process admission for active connections, attempts and tracked source
  addresses, total Homes, and aggregate queued payload bytes.

The legacy Node protocol, Firestore listeners, FCM sender, and custom `miakode`
encoding are intentionally absent. Miakapp 3.5 has no permanent v3 compatibility
path in the relay.

## Development

Requirements:

- Go 1.26.6
- Docker for image checks
- Bun 1.2.23, Node.js 22.22 or newer, and the exact Playwright Chromium runtime
  from MiakAPI for the optional SDK/browser integration check
- Java 21 and OpenSSL for the optional full control-plane integration check

Run the Go checks:

```sh
go test -race ./...
go vet ./...
```

Run the real MiakAPI coordinator and browser integration after installing its
dependencies, browser runtime, and building a local MiakAPI checkout:

```sh
cd /absolute/path/to/MiakAPI
bun install --frozen-lockfile
bunx playwright install chromium
bun run build
cd /absolute/path/to/Miakapp-Server
./scripts/check-miakapi-integration.sh /absolute/path/to/MiakAPI
```

This smaller gate serves the MiakAPI browser fixture from loopback HTTPS, allows
exactly that page Origin, and executes it in headless Chromium against the real
relay.
It proves enrollment, initial state, one patch, one call/result and scheduled
reauthentication on one WebSocket. A second call succeeds after the original
four-second lease expires, proving the correlated renewal completed without a
reconnect. The fixture uses only synthetic tokens and emits a closed semantic
JSON result; browser traces and WebSocket frame inspection stay disabled. It
does not exercise the control-plane credential exchange or memory isolation
from a malicious relay.

Run the production authentication adapter against the canonical control-plane
vectors:

```sh
./scripts/check-control-plane-integration.sh /absolute/path/to/Miakapp-V3
```

Run the synthetic Home Key and browser source credentials through the real
emulator control plane, MiakAPI providers, scheduled SDK reauthentication, and
production relay verifier after building both external checkouts:

```sh
./scripts/check-platform-integration.sh /absolute/path/to/Miakapp-V3 /absolute/path/to/MiakAPI
```

This gate uses only loopback HTTPS, the `demo-miakapp-v4` Auth and Firestore
emulators, ephemeral certificates, Home Key and control-secret files, and two
independent instances of the production verifier cache. It creates an unenrolled
synthetic Auth user and a signed synthetic App Check token in one private
temporary file. Because the Auth emulator emits deliberately unsigned JWTs, the
browser fixture applies a local shape adapter before the strict public provider
and restores the exact emulator token at the HTTPS boundary; production code is
not relaxed. The real control plane then issues the audience-bound user token.

A fake-clock probe cache proves one shared refresh for 32 concurrent future-key
tokens, the ten-second random-`kid` abuse bound, conditional expiry revalidation,
fail-closed outage handling, and bounded recovery. The real-time relay cache
survives signing-key rotation while a coordinator and a real Chromium browser
each complete same-socket `REAUTH`. The fixture then changes the authoritative
Home relay, and the browser carries that single new credential to a second real
relay without another exchange or overlapping sockets. It recovers state and
executes calls on both relays. Integration-only constructors and authenticated
loopback controls are excluded from normal relay builds; transient frame checks
emit only bounded counters and a source-credential-presence boolean, never
tokens, claims, or frame contents. This local gate does not claim live Cloud KMS
rotation or public-ingress behavior.

CI checks out both repositories at immutable commits so relay changes cannot
silently drift against moving protocol, authentication, or SDK dependencies.

Build the binary and image:

```sh
go build ./cmd/miakapp-server
docker build -t miakapp-server:development .
```

The executable reads:

| Variable | Default | Purpose |
|---|---:|---|
| `MIAKAPP_LISTEN_ADDRESS` | `:3000` | HTTP listen address |
| `MIAKAPP_ALLOWED_ORIGINS` | empty | Comma-separated exact `http(s)://host[:port]` browser origins |
| `MIAKAPP_CONTROL_PLANE_ISSUER` | required | Exact HTTPS control-plane issuer origin |
| `MIAKAPP_CONTROL_PLANE_JWKS_URL` | required | Same-origin `/.well-known/jwks.json` endpoint |
| `MIAKAPP_RELAY_AUDIENCE` | required | Exact public `wss://.../ws` URL for this relay |
| `MIAKAPP_HANDSHAKE_TIMEOUT` | `5s` | Maximum wait for HELLO and authentication |
| `MIAKAPP_WRITE_TIMEOUT` | `5s` | One WebSocket write deadline |
| `MIAKAPP_PING_INTERVAL` | `30s` | RFC 6455 liveness interval |
| `MIAKAPP_PONG_TIMEOUT` | `10s` | Pong deadline |
| `MIAKAPP_DECLARATION_TIMEOUT` | `30s` | Incomplete declaration transaction lifetime |
| `MIAKAPP_DISCONNECT_GRACE` | `30s` | Retained coordinator generation lifetime |
| `MIAKAPP_SHUTDOWN_TIMEOUT` | `10s` | HTTP shutdown deadline |
| `MIAKAPP_MAX_QUEUED_BYTES` | `1048576` | Per-connection outbound byte ceiling |
| `MIAKAPP_MAX_CONNECTIONS` | `256` | Process-wide active WebSocket ceiling |
| `MIAKAPP_MAX_CONNECTIONS_PER_IP` | `32` | Active WebSocket ceiling for one immediate TCP peer |
| `MIAKAPP_CONNECTION_ATTEMPTS_PER_MINUTE` | `120` | Fixed-window attempt ceiling for one immediate TCP peer |
| `MIAKAPP_MAX_TRACKED_IPS` | `4096` | Process-wide ceiling for in-memory source admission buckets |
| `MIAKAPP_MAX_HOMES` | `1024` | Process-wide live and grace-retained Home ceiling |
| `MIAKAPP_MAX_AGGREGATE_QUEUED_BYTES` | `67108864` | Shared outbound queue byte ceiling across all connections |

An absent HTTP `Origin` is accepted for non-browser clients. A supplied browser
origin must match one configured value exactly; wildcards, substring matching,
paths, queries, and fragments are rejected.

## Authentication boundary

`internal/auth.Verifier` is the sole credential boundary. It returns a bounded
identity lease; the relay independently binds that lease to the requested role,
home, coordinator name, principal ID, Home Key client ID, and expiry.
Reauthentication cannot change the established principal or switch Home Keys.

Coordinator, CLI, and browser-user tokens use distinct canonical Ed25519
profiles from RFC 0004. The browser profile contains exactly one relay audience,
Home ID, Firebase UID, `miakapp_role=user`, `scope=relay:user`, a maximum
five-minute lease, and an optional verified email; it contains no Home Key client
or coordinator claim. HELLO may only bind the already verified user to the same
Home. Firebase ID and App Check tokens are rejected as relay credentials.

The relay pins one issuer, one audience, and one same-origin JWKS URL. The JWKS
client accepts no redirects, bounds responses to 64 KiB and 16 exact Ed25519
keys, requires the specified ETag and 60-second cache policy, coalesces concurrent
refreshes, and permits at most one unknown-key refresh per ten seconds. Expired
caches fail closed if they cannot be refreshed.

The selected relay still observes plaintext Home traffic and must therefore be
an official instance, self-hosted by the user, or operated by somebody the user
explicitly trusts. Self-hosting requires configuring the relay's exact public
WSS URL in the authoritative Home record and as `MIAKAPP_RELAY_AUDIENCE`; a token
issued for another relay cannot be replayed here. The relay needs only public
control-plane configuration and no Firebase or Miakapp credential.

This credential transition is intentionally fail-closed rather than dual-stack:
an old Firebase-token relay rejects the new user profile, and this relay rejects
Firebase source tokens. Roll out compatible control-plane, browser SDK, and relay
revisions together, retain the previous complete set for rollback, and do not
route browser traffic to a partially upgraded relay.

Process admission is applied before WebSocket upgrade. It keys active and
fixed-minute attempt limits only by `RemoteAddr`, the immediate TCP peer, and
never trusts `X-Forwarded-For` or another caller-controlled header. A shared
reverse proxy can therefore make this deliberately coarser than an end-user IP;
deployments that require client-level fairness must enforce it at a trusted edge.
The independent process-wide connection ceiling still bounds work in either
case. Source buckets, live and grace-retained Homes, per-connection queues and
aggregate queued bytes all have finite configurable ceilings. Complete frames,
subscriptions, calls, declared home dictionaries, presence and coordinator
counts retain their protocol bounds.

## Trust and persistence

The relay contains no platform secret and makes no authenticated outbound call.
Its deployment ingress terminates WSS before the Go process handles plaintext
home data, so a home trusts its selected relay operator for confidentiality and
correct routing. This is not end-to-end encryption.

All home state is in memory. A relay restart creates new home epochs and requires
coordinators to declare complete slices again. Protocol 1.0 has no session replay
or durable event delivery.
