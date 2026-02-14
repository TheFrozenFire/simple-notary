# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run Commands

```bash
cargo build                      # Build all crates
cargo build -p simple-notary     # Build notary server only
cargo build -p simple-notary-client  # Build client only
cargo test                       # Run all tests (currently only doctests in axum-websocket)
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
2. **`notarize.rs`** — Core notarization handler. Wraps the WebSocket in a `WsStream` for `AsyncRead`/`AsyncWrite`, passes it through the Yoinker pattern, runs the TLSNotary `Verifier`, extracts the transcript, builds an `HttpContext`, and sends the JSON result back.
3. **`yoinker.rs`** — `IoYoinker`/`IoBoinker` pattern using `Arc`/`Weak<Mutex<T>>`. Temporarily hands the WebSocket I/O to the TLSNotary verifier (which consumes the stream), then recovers ownership afterward to send results back over the same connection.
4. **`error.rs`** — `NotaryServerError` enum with `IntoResponse` impl for HTTP error mapping.

### Key Dependencies

- `tlsn` (v0.1.0-alpha.13) — TLSNotary protocol implementation (verifier side)
- `http-transcript-context` — Custom crate for parsing TLS transcripts into HTTP context (from `thefrozenfire/web-transcript-parser`)
- `async-tungstenite` + `ws_stream_tungstenite` — WebSocket with `AsyncRead`/`AsyncWrite` support
- `axum` 0.8 — HTTP framework

### Incomplete Areas

- `proxy.rs` — Declared as a module but empty
- Client crate — Skeleton only, no prover implementation
- Binary output format in `notarize.rs` — Commented out
