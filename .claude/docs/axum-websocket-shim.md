# axum-websocket Shim

## Problem

TLSNotary's `Verifier::setup()` requires a stream implementing `futures::io::AsyncRead + AsyncWrite`. Axum's built-in WebSocket (`axum::extract::ws`) uses `tokio-tungstenite` internally, which doesn't expose the raw `WebSocketStream` needed by `ws_stream_tungstenite` to provide these traits.

## Solution

The `axum-websocket` crate is a fork of `axum/src/extract/ws.rs` (from axum v0.8.0) with `tokio-tungstenite` swapped for `async-tungstenite`. This allows wrapping the connection with `ws_stream_tungstenite::WsStream`, which implements `AsyncRead + AsyncWrite` on top of a `WebSocketStream`.

## Key Modifications (marked with `NOTARY_MODIFICATION` comments in source)

1. **Import swap**: `async_tungstenite` replaces `tokio_tungstenite` throughout
2. **`TokioAdapter` wrapper**: `async_tungstenite::tokio::TokioAdapter` wraps `hyper::upgrade::Upgraded` since it doesn't implement the futures crate's async I/O traits natively
3. **`into_inner()` / `from_inner()`**: Added to `WebSocket` to expose the underlying `WebSocketStream` — this is how `server.rs` extracts the stream for TLSNotary
4. **`header_eq()` made public**: Used by `server.rs` `ProtocolUpgrade` extractor to check the Upgrade header
5. **`Utf8Bytes` shimmed**: `async-tungstenite` v0.28 uses an older `tungstenite` that lacks `Utf8Bytes`, so it's wrapped around `axum::extract::ws::Utf8Bytes` with conversions via `.to_string()` / `.into()`
6. **Message conversions**: `into_tungstenite()` / `from_tungstenite()` adapted for the older tungstenite API (uses `String`/`Vec<u8>` instead of `Utf8Bytes`/`Bytes`)
7. **HTTP/2 protocol check disabled**: The `hyper::ext::Protocol` check is commented out

## Type Chain

```
axum WebSocket upgrade
  → hyper::upgrade::Upgraded
    → TokioIo<Upgraded>
      → TokioAdapter<TokioIo<Upgraded>>    (async-tungstenite compat)
        → WebSocketStream<TokioAdapter<...>>  (tungstenite framing)
          → ws_stream_tungstenite::WsStream   (AsyncRead + AsyncWrite)
```

## When Updating

If upgrading axum or tungstenite versions, check:
- Does `async-tungstenite` support the new tungstenite version? The `Utf8Bytes` shim exists because of version skew.
- Does `ws_stream_tungstenite` support the new `async-tungstenite` version?
- Re-diff against upstream `axum/src/extract/ws.rs` for any new changes to port.
