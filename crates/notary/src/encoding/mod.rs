mod json;
mod abi;
mod eip712;

pub use json::JsonEncoder;
pub use abi::AbiEncoder;
pub use eip712::Eip712Encoder;

/// The result of encoding an HTTP context for signing.
pub struct EncodedContext {
    /// Encoded representation (for transmission).
    pub data: Vec<u8>,
    /// Hash digest to be signed.
    pub digest: Vec<u8>,
}

/// Trait for encoding HTTP context into a format suitable for signing.
///
/// The encoder owns both serialization and hashing — it produces the
/// encoded data and the digest that the signer will sign.
pub trait ContextEncoder: Send + Sync {
    /// Encode the context value and compute the signing digest.
    fn encode(&self, context: &serde_json::Value) -> anyhow::Result<EncodedContext>;

    /// Format name (e.g. "json", "abi", "eip712").
    fn name(&self) -> &str;
}
