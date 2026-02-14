pub mod server;
pub mod notarize;
pub mod error;
pub mod signing;
pub mod encoding;

pub use server::{AppState, run, router};
pub use notarize::notarize;
pub use signing::{ContextSigner, Secp256k1Signer, RsaSigner, EthereumSecp256k1Signer};
pub use encoding::{ContextEncoder, EncodeOptions, Quantization, EncodedContext, JsonEncoder, AbiEncoder, Eip712Encoder};
#[cfg(feature = "embedding")]
pub use encoding::EmbeddingEncoder;
