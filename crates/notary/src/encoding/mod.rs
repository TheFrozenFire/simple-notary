mod json;
mod abi;
mod eip712;
#[cfg(feature = "embedding")]
mod embedding;

pub use json::JsonEncoder;
pub use abi::AbiEncoder;
pub use eip712::Eip712Encoder;
#[cfg(feature = "embedding")]
pub use embedding::EmbeddingEncoder;

use serde::{Serialize, Deserialize};

/// Options passed from the prover's message to the encoder.
///
/// Most encoders ignore these; the embedding encoder uses them to select
/// the model and quantization strategy.
#[derive(Debug, Default, Clone)]
pub struct EncodeOptions {
    pub embedding_model: Option<String>,
    pub quantization: Option<Quantization>,
}

/// Quantization format for embedding vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Quantization {
    Float32,
    Int8,
}

/// The result of encoding an HTTP context for signing.
#[derive(Debug)]
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
    fn encode(&self, context: &serde_json::Value, options: &EncodeOptions) -> anyhow::Result<EncodedContext>;

    /// Format name (e.g. "json", "abi", "eip712", "embedding").
    fn name(&self) -> &str;

    /// Models available for embedding (empty for non-embedding encoders).
    fn available_models(&self) -> Vec<String> {
        vec![]
    }
}
