/// Trait for signing pre-computed digests of HTTP context data.
///
/// The encoder owns hashing — signers receive a pre-computed digest.
/// Implementations are sync — signing is CPU-bound.
/// For async backends (e.g. KMS), use `spawn_blocking`.
pub trait ContextSigner: Send + Sync {
    /// Sign a pre-computed digest. Returns raw signature bytes.
    fn sign_digest(&self, digest: &[u8]) -> anyhow::Result<Vec<u8>>;

    /// Compressed public key bytes (e.g. 33 bytes for secp256k1).
    fn public_key_bytes(&self) -> Vec<u8>;

    /// Algorithm identifier string (e.g. "secp256k1").
    fn algorithm(&self) -> &str;
}
