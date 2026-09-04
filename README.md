# Miakapp Server

Miakapp Server is the in-memory Go relay for the Miakapp 3.5 protocol. It
connects home coordinators, authenticated users, and future CLI sessions without
holding Firebase credentials, Home Keys, push credentials, or product business
logic.

This repository currently contains an implementation preview of the relay/SDK vertical slice. The
engine is usable through its injected authentication interface and its tests,
but the standalone binary intentionally rejects every WebSocket authentication
attempt until the canonical platform control-plane contract defines token
claims, JWKS rotation, scopes, and revocation. `/ping` remains available for
container and network validation. Do not deploy this preview as a production
replacement.

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

CI checks out the SDK at an immutable commit so relay changes cannot silently
drift against a moving integration dependency.

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
home, coordinator name, principal ID, and expiry. Reauthentication cannot change
the established principal.

The production verifier is deliberately not guessed here. The next control-plane
contract must define owner bootstrap, Home Key exchange, access-token claims,
audience selection, scopes, signing/JWKS rotation, revocation, push grants, and
publisher authorization together. Until that contract lands, the standalone
entry point uses `RejectingVerifier` and fails closed.

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
