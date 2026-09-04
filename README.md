# Miakapp Server

Miakapp Server is the in-memory Go relay for the Miakapp 3.5 protocol. It
connects home coordinators, authenticated users, and future CLI sessions without
holding Firebase credentials, Home Keys, push credentials, or product business
logic.

The standalone binary validates short-lived coordinator and CLI access tokens
against the configured control-plane JWKS and validates human sessions against
Firebase public certificates. It holds no verification secret and never calls
the platform with authenticated authority. The relay remains an implementation
preview until deployment admission limits and the staging relay integration gate
have passed; do not deploy it as a production replacement yet.

## Contract

The wire contract is owned by Miakapp-V3
[`RFC 0001`](https://github.com/Miakapp/Miakapp-V3/blob/b927789691dd8cdebc91b673853cdc6711fe057d/docs/rfcs/0001-wire-protocol.md).
This module pins the independent canonical Go codec at that immutable commit.
It does not copy frame definitions into this repository.

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
- byte-bounded outbound queues and stable protocol errors.

The legacy Node protocol, Firestore listeners, FCM sender, and custom `miakode`
encoding are intentionally absent. Miakapp 3.5 has no permanent v3 compatibility
path in the relay.

## Development

Requirements:

- Go 1.26.6
- Docker for image checks
- Bun 1.2.23 and Node.js 22.22 or newer for the optional MiakAPI integration
  check

Run the Go checks:

```sh
go test -race ./...
go vet ./...
```

Run the real MiakAPI coordinator integration after building a local MiakAPI
checkout:

```sh
./scripts/check-miakapi-integration.sh /absolute/path/to/MiakAPI
```

Run the production authentication adapter against the canonical control-plane
vectors:

```sh
./scripts/check-control-plane-integration.sh /absolute/path/to/Miakapp-V3
```

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
| `MIAKAPP_FIREBASE_PROJECT_ID` | required | Firebase project accepted for human sessions |
| `MIAKAPP_HANDSHAKE_TIMEOUT` | `5s` | Maximum wait for HELLO and authentication |
| `MIAKAPP_WRITE_TIMEOUT` | `5s` | One WebSocket write deadline |
| `MIAKAPP_PING_INTERVAL` | `30s` | RFC 6455 liveness interval |
| `MIAKAPP_PONG_TIMEOUT` | `10s` | Pong deadline |
| `MIAKAPP_DECLARATION_TIMEOUT` | `30s` | Incomplete declaration transaction lifetime |
| `MIAKAPP_DISCONNECT_GRACE` | `30s` | Retained coordinator generation lifetime |
| `MIAKAPP_SHUTDOWN_TIMEOUT` | `10s` | HTTP shutdown deadline |
| `MIAKAPP_MAX_QUEUED_BYTES` | `1048576` | Per-connection outbound byte ceiling |

An absent HTTP `Origin` is accepted for non-browser clients. A supplied browser
origin must match one configured value exactly; wildcards, substring matching,
paths, queries, and fragments are rejected.

## Authentication boundary

`internal/auth.Verifier` is the sole credential boundary. It returns a bounded
identity lease; the relay independently binds that lease to the requested role,
home, coordinator name, principal ID, Home Key client ID, and expiry.
Reauthentication cannot change the established principal or switch Home Keys.

Coordinator and CLI tokens use the canonical Ed25519 profile from RFC 0004. The
relay pins one issuer, one audience and one same-origin JWKS URL. The JWKS client
accepts no redirects, bounds responses to 64 KiB and 16 exact Ed25519 keys,
requires the specified ETag and 60-second cache policy, coalesces concurrent
refreshes, and permits at most one unknown-key refresh per ten seconds. Expired
caches fail closed if they cannot be refreshed.

Human sessions use Firebase ID tokens, the pinned Firebase project/issuer and
Google's fixed Secure Token certificate endpoint. Certificate lifetime follows
the endpoint's `Cache-Control` maximum age. This local verification deliberately
does not claim immediate Firebase account-disablement or token-revocation checks;
the browser must reauthenticate before its current ID-token lease expires.

This preview is not yet the deployment admission-control boundary. Per-IP
connection limits, total-home admission, and aggregate cross-connection memory
budgets must land with that control-plane/deployment contract. The relay already
bounds complete frames, each connection queue, subscriptions, calls, declared
home dictionaries, presence, and coordinator counts.

## Trust and persistence

The relay contains no platform secret and makes no authenticated outbound call.
Its deployment ingress terminates WSS before the Go process handles plaintext
home data, so a home trusts its selected relay operator for confidentiality and
correct routing. This is not end-to-end encryption.

All home state is in memory. A relay restart creates new home epochs and requires
coordinators to declare complete slices again. Protocol 1.0 has no session replay
or durable event delivery.
