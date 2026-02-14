# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run Commands

```bash
cargo build                      # Build all crates
cargo build -p simple-notary     # Build notary server only
cargo build -p simple-notary-client  # Build client only
cargo test                       # Run all tests
cargo test -p axum-websocket     # Run tests for a specific crate
cargo run -p simple-notary       # Run notary server (default: 127.0.0.1:3000)
cargo run -p simple-notary -- --host 0.0.0.0 --port 8080  # Custom host/port
```

## Architecture

This is a **TLSNotary** service — a third-party verifier that cryptographically attests to the authenticity of TLS communications between a prover and a server, without access to the server's private key.

### Crates

- **`notary`** (package: `simple-notary`) — Axum HTTP server with a `/notarize` WebSocket endpoint. Accepts prover connections, runs the TLSNotary verifier protocol, extracts the transcript, and sends results back over the same WebSocket.
- **`client`** (package: `simple-notary-client`) — Prover client. Currently a stub with no real implementation.
- **`axum-websocket`** — Fork of Axum's WebSocket module that swaps `tokio-tungstenite` for `async-tungstenite`. This enables `AsyncRead`/`AsyncWrite` via `ws_stream_tungstenite`, which TLSNotary requires for its protocol streams.

### Key Flow (notary crate)

1. **`server.rs`** — Sets up Axum router with `/healthcheck` and `/notarize` routes. The `/notarize` endpoint accepts WebSocket upgrades with a `context_format` query param (json or binary).
2. **`notarize.rs`** — Core notarization handler. Creates a `Session` over the `WsStream`, runs the TLSNotary `Verifier` through its state machine (commit → accept → run → verify → accept), extracts the transcript, closes the session to reclaim I/O, and returns both the transcript and the recovered stream.
3. **`error.rs`** — `NotaryServerError` enum with `IntoResponse` impl for HTTP error mapping.

### Key Dependencies

- `tlsn` (v0.1.0-alpha.14) — TLSNotary protocol implementation (verifier side, Session-based API)
- `http-transcript-context` — Custom crate for parsing TLS transcripts into HTTP context (from `thefrozenfire/web-transcript-parser`)
- `async-tungstenite` + `ws_stream_tungstenite` — WebSocket with `AsyncRead`/`AsyncWrite` support
- `axum` 0.8 — HTTP framework

### Incomplete Areas

- Client crate — Skeleton only, no prover implementation
- Binary output format in `notarize.rs` — Not yet implemented (`todo!()`)

## Deep Docs

See `.claude/docs/` for detailed internal documentation:

- [axum-websocket-shim.md](docs/axum-websocket-shim.md) — Why the axum-websocket fork exists and what was changed
- [session-io-reclamation.md](docs/session-io-reclamation.md) — How the Session API handles I/O ownership and reclamation
- [notarization-flow.md](docs/notarization-flow.md) — End-to-end data flow through the notarization pipeline
- [tlsn-releases.md](docs/tlsn-releases.md) — TLSNotary release notes (alpha.10–alpha.14) and upgrade migration guide
- [notarization-strategies.md](docs/notarization-strategies.md) — Planned evolution: full-context signing → selective disclosure → pluggable transformation strategies
