# Session-Based I/O Reclamation (tlsn alpha.14)

## Problem

The TLSNotary verifier protocol consumes an I/O stream during the MPC-TLS exchange. After notarization completes, we need to send results back to the client over the **same WebSocket connection**. Previously this required the custom Yoinker pattern (`Arc`/`Weak<Mutex<T>>`), but alpha.14's `Session` type handles this natively.

## How It Works

The `Session<Io>` type wraps an `AsyncRead + AsyncWrite` stream and provides:
- **Multiplexing** — multiple logical channels over a single transport
- **I/O reclamation** — the original stream is returned when the session closes

### Lifecycle

```rust
// 1. Create session over the WebSocket stream
let session = Session::new(ws_stream);

// 2. Split into driver (owns I/O) and handle (control interface)
let (driver, mut handle) = session.split();

// 3. Spawn driver as a background task — it manages the underlying I/O
let driver_task = tokio::spawn(driver);

// 4. Use handle to create verifier and run protocol
let verifier = handle.new_verifier(config)?;
// ... run verifier state machine ...

// 5. Close the verifier and handle
verifier.close().await?;
handle.close();

// 6. Await driver — it returns the original I/O stream
let ws_stream = driver_task.await??;

// 7. Write results back over the reclaimed stream
ws_stream.write_all(result_bytes).await?;
```

### Key Differences from Yoinker

| Aspect | Yoinker (old) | Session (new) |
|--------|--------------|---------------|
| Ownership | `Arc`/`Weak` shared refs | Driver task owns I/O exclusively |
| Reclamation | `Arc::try_unwrap()` | Driver returns I/O on completion |
| Error handling | Panic if refs still held | Type-safe via `JoinHandle` |
| Complexity | Custom implementation | Built into tlsn |
| `compat()` needed | Yes (`tokio_util::compat`) | No — works with `futures::io` directly |

## Why This Is Better

- No `unsafe`-adjacent patterns (`Arc::try_unwrap` can panic)
- No `tokio-util` dependency for `.compat()` bridging
- The session driver handles protocol multiplexing transparently
- I/O reclamation is a first-class feature, not a workaround
