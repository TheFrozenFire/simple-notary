use anyhow::Result;
use alloy_primitives::{Address, U256};
use alloy_sol_types::{Eip712Domain, SolStruct, SolValue};

use super::abi::parse_attestation;
use super::{ContextEncoder, EncodedContext};

/// Encodes context as ABI-encoded structs with EIP-712 typed data digest.
///
/// Uses the same ABI struct layout as `AbiEncoder`, but the digest is the
/// standard EIP-712 signing hash: `keccak256("\x19\x01" || domainSeparator || structHash)`.
pub struct Eip712Encoder {
    domain: Eip712Domain,
}

impl Eip712Encoder {
    pub fn new(
        name: String,
        version: String,
        chain_id: u64,
        verifying_contract: [u8; 20],
    ) -> Self {
        let domain = Eip712Domain::new(
            Some(name.into()),
            Some(version.into()),
            Some(U256::from(chain_id)),
            Some(Address::from(verifying_contract)),
            None,
        );
        Self { domain }
    }
}

impl ContextEncoder for Eip712Encoder {
    fn encode(&self, context: &serde_json::Value) -> Result<EncodedContext> {
        let attestation = parse_attestation(context)?;
        let data = attestation.abi_encode();
        let digest = attestation
            .eip712_signing_hash(&self.domain)
            .to_vec();
        Ok(EncodedContext { data, digest })
    }

    fn name(&self) -> &str {
        "eip712"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::abi::Attestation;
    use alloy_sol_types::SolValue;
    use serde_json::json;

    fn test_encoder() -> Eip712Encoder {
        Eip712Encoder::new(
            "SimpleNotary".to_string(),
            "1".to_string(),
            1,
            [0u8; 20],
        )
    }

    #[test]
    fn encode_produces_eip712_digest() {
        let encoder = test_encoder();
        let context = json!({
            "requests": [{"target": "/", "method": "GET", "headers": [], "body": null}],
            "responses": [{"status": 200, "headers": [], "body": null}]
        });

        let encoded = encoder.encode(&context).unwrap();
        assert_eq!(encoded.digest.len(), 32, "EIP-712 digest should be 32 bytes");
        assert!(!encoded.data.is_empty());

        // Verify the data is valid ABI encoding
        let decoded = <Attestation as SolValue>::abi_decode(&encoded.data, true).unwrap();
        assert_eq!(decoded.requests.len(), 1);
    }

    #[test]
    fn digest_differs_from_abi_encoder() {
        use super::super::abi::AbiEncoder;
        use super::super::ContextEncoder;

        let abi_encoder = AbiEncoder;
        let eip712_encoder = test_encoder();
        let context = json!({
            "requests": [{"target": "/", "method": "GET", "headers": [], "body": null}],
            "responses": [{"status": 200, "headers": [], "body": null}]
        });

        let abi_encoded = abi_encoder.encode(&context).unwrap();
        let eip712_encoded = eip712_encoder.encode(&context).unwrap();

        // Same data bytes (both ABI-encode the same struct)
        assert_eq!(abi_encoded.data, eip712_encoded.data);
        // Different digests (keccak256 vs EIP-712 signing hash)
        assert_ne!(abi_encoded.digest, eip712_encoded.digest);
    }

    #[test]
    fn deterministic_signing_hash() {
        let encoder = test_encoder();
        let context = json!({
            "requests": [],
            "responses": []
        });
        let enc1 = encoder.encode(&context).unwrap();
        let enc2 = encoder.encode(&context).unwrap();
        assert_eq!(enc1.digest, enc2.digest);
    }

    #[test]
    fn different_domains_produce_different_digests() {
        let encoder_a = Eip712Encoder::new("AppA".to_string(), "1".to_string(), 1, [0u8; 20]);
        let encoder_b = Eip712Encoder::new("AppB".to_string(), "1".to_string(), 1, [0u8; 20]);
        let context = json!({
            "requests": [],
            "responses": []
        });

        let enc_a = encoder_a.encode(&context).unwrap();
        let enc_b = encoder_b.encode(&context).unwrap();
        assert_ne!(enc_a.digest, enc_b.digest);
    }

    #[test]
    fn name_is_eip712() {
        assert_eq!(test_encoder().name(), "eip712");
    }
}
