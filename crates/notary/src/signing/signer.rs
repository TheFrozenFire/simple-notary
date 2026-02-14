/// Trait for signing serialized HTTP context data.
///
/// Implementations are sync — signing is CPU-bound.
/// For async backends (e.g. KMS), use `spawn_blocking`.
pub trait ContextSigner: Send + Sync {
    /// Sign canonical bytes. Returns raw signature bytes.
    fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>>;

    /// Compressed public key bytes (e.g. 33 bytes for secp256k1).
    fn public_key_bytes(&self) -> Vec<u8>;

    /// Algorithm identifier string (e.g. "secp256k1").
    fn algorithm(&self) -> &str;
}
