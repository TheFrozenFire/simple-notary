# TLSNotary (`tlsn`) Release Notes

This project currently depends on `tlsn` **v0.1.0-alpha.13**. This document summarizes recent releases and the migration path to alpha.14.

---

## v0.1.0-alpha.14 (2026-01-14) — NEXT VERSION

The biggest release since alpha.13. Major API overhaul affecting how this project creates and uses the Verifier.

### New `Session` type (breaking)

Verifiers (and Provers) are no longer created directly. Instead, a `Session<Io>` manages the connection and multiplexing. This replaces the old pattern of passing a socket directly to `Verifier::setup()`.

**Old API (alpha.13 — what we use now):**
```rust
let verifier = Verifier::new(config);
let verifier = verifier.setup(socket).await?;  // consumes socket, sets up mux internally
let verifier = verifier.run().await?;
let output = verifier.verify(&VerifyConfig::default()).await?;
```

**New API (alpha.14):**
```rust
let mut session = Session::new(io);            // wraps the I/O stream
let verifier = session.new_verifier(config)?;  // creates verifier from session

// Session must be polled concurrently:
let (driver, handle) = session.split();
tokio::spawn(driver);  // drives the connection in background

let verifier = verifier.commit().await?;       // receive prover's config
let verifier = verifier.accept().await?;       // accept or reject config
let verifier = verifier.run().await?;          // MPC-TLS execution
let verifier = verifier.verify().await?;       // begin verification
let (output, verifier) = verifier.accept().await?;  // accept prove request

// Reclaim I/O after session closes
handle.close();
let io = handle.try_take()?;
```

**Key differences:**
- `Verifier::new(config)` → `session.new_verifier(config)?` (verifier is created from session, not standalone)
- `Verifier::setup(socket)` is gone — `Session::new(io)` handles connection setup and muxing
- The session must be polled (via `split()` + spawning the driver, or polling `Session` as a `Future`)
- Config validation is now explicit: `commit()` → inspect `request()` → `accept()` or `reject(msg)`
- `verify()` now returns a state where you can inspect the `ProveRequest` and `accept()`/`reject()` it
- I/O can be reclaimed via `session.try_take()` after closing — this could **replace our Yoinker pattern**

### Inversion of control for config validation (breaking)

`ProtocolConfigValidator` is removed. Instead, the verifier receives the prover's `TlsCommitRequest` via `commit()` and decides to `accept()` or `reject(msg)`. Rejection messages propagate to the prover's `Error::msg()`.

**Old:**
```rust
let validator = ProtocolConfigValidator::builder().build()?;
let config = VerifierConfig::builder()
    .protocol_config_validator(validator)
    .build()?;
```

**New:** Config validation happens at `commit()` time — inspect `verifier.request()` and call `accept()` or `reject("reason")`.

### Consolidated error type (breaking)

`VerifierError` and `ProverError` are replaced by a single `tlsn::Error` with kind categorization:
- `error.is_user()` — rejected by remote party
- `error.is_io()` — network/communication failure
- `error.is_internal()` — library bug
- `error.is_config()` — invalid configuration
- `error.msg()` — additional context (e.g., rejection reason)

### `tlsn_insecure` mode

Compile with `RUSTFLAGS='--cfg tlsn_insecure'` to skip expensive crypto for integration testing. **Never use in production.**

### Transcript commitments

- `TranscriptCommitmentKind::Encoding` deprecated (non-standard, obsoleted by hash commitments)
- `HashAlgId::KECCAK256` support added

### Impact on this project

Upgrading to alpha.14 would require:
1. Replace `Verifier::new(config).setup(socket)` with `Session::new(io)` + `session.new_verifier(config)`
2. Remove `ProtocolConfigValidator` — implement accept/reject logic in the `commit()` → `accept()` flow
3. Replace `VerifierError` with `tlsn::Error`
4. Spawn the session driver for concurrent polling
5. **Potentially remove the Yoinker pattern** — `Session::try_take()` provides native I/O reclamation
6. Update `VerifierOutput` access — `verify()` now returns a two-step accept/reject flow

---

## v0.1.0-alpha.13 (2025-10-15) — CURRENT VERSION

### API consolidation

The `prover` and `verifier` crates were merged into the single `tlsn` crate, which also re-exports `core` types. Only one dependency needed: `tlsn`.

### Notary server/client removed from repo

`notary-server` and `notary-client` were removed from the tlsn repo to focus on core protocol. This is why projects like simple-notary exist — the upstream team expects consumers to build their own notary services.

### Performance improvements

- **Selective disclosure**: redacted data incurs zero proving overhead (only pay for what you disclose)
- **Full transcript disclosure**: if disclosing entire sent or received transcript, no additional overhead — enables proving megabytes of data
- **BLAKE3** transcript commitments added (fast, SIMD/WASM-friendly)

### Other

- `TranscriptCommitConfig` API for hash commitment selection
- `PartialTranscript` decoupled from `ProveConfig`
- `RangeSet` replaces `Idx` for transcript indexing

---

## v0.1.0-alpha.12 (2025-06-19)

- **JWT auth** for notary server (`Authorization: Bearer <token>`)
- **Benchmarking harness** CLI for native and browser environments
- **Mutual TLS (mTLS)** — prover can present client certificates during TLS handshake
- MPC optimizations for reduced protocol runtime
- Concurrent OT setup and garbled circuit preprocessing

---

## v0.1.0-alpha.11 (2025-05-27)

- **Attestation decoupling begins** — deprecation warning on notarize methods; attestation functionality being extracted to dedicated `tlsn-attestation` crate
- **SHA256 transcript hash commitments** — prove hash of transcript data to verifier (simpler and more performant than encoding commitments)
- **Network optimization mode** — `ProtocolConfigBuilder::network(NetworkSetting::Latency)` for low-bandwidth connections (~10Mbps), reduces prover-to-verifier upload
- Notary server simplified — starts without config file, auto-generates signing keys

---

## v0.1.0-alpha.10 (2025-04-18)

- **Attestation extensions** — custom data from prover/notary in attestations (e.g., prover public key for identity binding)
- **TranscriptProofBuilder** simplified — auto-selects best commitments to open
- **Concurrency limit** for notary server
