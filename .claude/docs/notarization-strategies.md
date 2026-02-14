# Notarization Strategies

## Current State

The notary returns the full `HttpContext` (parsed HTTP requests/responses from the TLS transcript) as a JSON blob over the reclaimed WebSocket. There is no cryptographic attestation — the prover receives raw transcript content and nothing more.

## Planned Evolution

The notary should return an additional component: a **notarization strategy** output. The flow becomes a two-phase exchange over the WebSocket:

1. **Transcript phase** — The MPC-TLS protocol runs, and the notary sends the `HttpContext` back to the prover (as today).
2. **Signing phase** — The prover examines the context and requests a signed version of it from the notary.

### Phase 1: Sign Full Context

Start simple. After the prover receives the context, it sends a signing request and the notary returns the entire context signed. This establishes the signing infrastructure and proves the end-to-end flow works.

### Phase 2: Selective Disclosure

Let the prover request a **subset** of the context to be signed. The prover chooses which parts of the transcript (specific headers, body fields, etc.) to include in the signed output. This gives the prover control over what they reveal to downstream verifiers.

### Phase 3: Transformation Strategies

Define pluggable **transformation strategies** that take the context as input and output it in different contextual formats. Examples:

- **On-chain attestation** — A signed message formatted for smart contract verification (e.g. EIP-712 typed data, or a compact binary format suitable for calldata).
- Other domain-specific formats as needed.

The strategy is selected by the prover and executed by the notary, producing a signed output in the requested format.
