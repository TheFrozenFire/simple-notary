use anyhow::{Context, Result};
use sha2::{Sha256, Digest};

use super::{ContextEncoder, EncodedContext};

/// Encodes context as canonical JSON with SHA-256 digest.
///
/// This is the default encoder that preserves backward compatibility
/// with the original signing exchange.
pub struct JsonEncoder;

impl ContextEncoder for JsonEncoder {
    fn encode(&self, context: &serde_json::Value) -> Result<EncodedContext> {
        let json_bytes = serde_json::to_string(context)
            .context("serializing context to canonical JSON")?
            .into_bytes();
        let digest = Sha256::digest(&json_bytes).to_vec();
        Ok(EncodedContext {
            data: json_bytes,
            digest,
        })
    }

    fn name(&self) -> &str {
        "json"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn roundtrip_encode() {
        let encoder = JsonEncoder;
        let context = json!({"request": {"method": "GET"}, "response": {"status": 200}});
        let encoded = encoder.encode(&context).unwrap();

        let decoded: serde_json::Value = serde_json::from_slice(&encoded.data).unwrap();
        assert_eq!(decoded, context);
    }

    #[test]
    fn digest_matches_sha256() {
        let encoder = JsonEncoder;
        let context = json!({"key": "value"});
        let encoded = encoder.encode(&context).unwrap();

        let expected_digest = Sha256::digest(&encoded.data).to_vec();
        assert_eq!(encoded.digest, expected_digest);
    }

    #[test]
    fn deterministic_encoding() {
        let encoder = JsonEncoder;
        let context = json!({"b": 2, "a": 1});
        let enc1 = encoder.encode(&context).unwrap();
        let enc2 = encoder.encode(&context).unwrap();
        assert_eq!(enc1.data, enc2.data);
        assert_eq!(enc1.digest, enc2.digest);
    }

    #[test]
    fn name_is_json() {
        assert_eq!(JsonEncoder.name(), "json");
    }
}
