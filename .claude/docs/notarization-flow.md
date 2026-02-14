# Notarization Flow

End-to-end data flow from HTTP request to transcript response.

## Sequence

```
Client (Prover)                          Notary Server
     |                                        |
     |  GET /notarize?context_format=json     |
     |  Upgrade: websocket                    |
     |--------------------------------------->|
     |                                        |  1. ProtocolUpgrade extractor (server.rs)
     |  101 Switching Protocols               |     validates Upgrade header
     |<---------------------------------------|
     |                                        |  2. on_upgrade callback fires
     |                                        |  3. socket.into_inner() → raw WebSocketStream
     |                                        |  4. WsStream::new(inner) → AsyncRead/Write
     |                                        |  5. Session::new(ws_stream)
     |                                        |     session.split() → (driver, handle)
     |                                        |     tokio::spawn(driver)
     |                                        |
     |  ←— TLSNotary protocol over WS ——→    |  6. notarize(ws_stream):
     |  (MPC-TLS verification messages)       |     handle.new_verifier(config)
     |                                        |     verifier.commit()
     |                                        |     verifier.accept()
     |                                        |     verifier.run()
     |                                        |     verifier.verify()
     |                                        |     verifier.accept() → VerifierOutput
     |                                        |
     |                                        |  7. Extract transcript:
     |                                        |     sent_unsafe, received_unsafe,
     |                                        |     sent_authed, received_authed
     |                                        |     → PartialTranscript
     |                                        |
     |                                        |  8. verifier.close(), handle.close()
     |                                        |  9. driver_task.await → reclaimed ws_stream
     |                                        | 10. HttpContext::builder(transcript).build()
     |                                        | 11. serde_json::to_value(context)
     |  JSON transcript context               |
     |<---------------------------------------|     write_all over reclaimed stream
     |                                        |
```

## Key Types Along the Path

### Transport Layer
- `axum_websocket::WebSocket` — Axum's WebSocket with `into_inner()`
- `WebSocketStream<TokioAdapter<TokioIo<Upgraded>>>` — raw tungstenite stream
- `ws_stream_tungstenite::WsStream` — adds `AsyncRead`/`AsyncWrite`
- `tlsn::Session<WsStream>` — wraps the stream, provides multiplexing and I/O reclamation

### TLSNotary Types
- `VerifierConfig` — configuration for the verifier instance
- `Verifier` — state machine: Initialized → CommitStart → CommitAccepted → Committed → Verify
- `VerifierOutput { server_name, transcript }` — verification result

### Transcript Types
- `tlsn` transcript — raw sent/received bytes with auth/unsafe partitions
- `PartialTranscript` (from `http-transcript-context`) — intermediate representation
- `HttpContext` — parsed HTTP request/response context, serializable to JSON

## I/O Reclamation

The `Session` API (alpha.14) natively handles I/O ownership. When `session.split()` is called, the driver task owns the underlying I/O. After the verifier protocol completes, calling `handle.close()` signals the driver to shut down, and `driver_task.await` returns the original I/O stream. This replaces the previous Yoinker pattern.

## Configuration

The `VerifierConfig` is built with an empty `RootCertStore`. No custom protocol limits, signing keys, or auth are configured.

## Output Formats

- **JSON** (`context_format=Json`): `HttpContext` serialized via serde_json, written as raw bytes to the reclaimed WebSocket stream
- **Binary** (`context_format=Binary`): Not yet implemented (`todo!()`)
