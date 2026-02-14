use anyhow::Result;
use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner, RecoveryId};
use sha2::{Sha256, Digest};

use super::signer::ContextSigner;

/// ECDSA signer using the secp256k1 curve with Ethereum-compatible
/// recoverable signatures (65 bytes: r + s + v).
///
/// The recovery ID (`v`) enables `ecrecover` in Solidity to recover
/// the signer's address from the signature without the public key.
pub struct EthereumSecp256k1Signer {
    signing_key: SigningKey,
}

impl EthereumSecp256k1Signer {
    pub fn from_seed(seed: &str) -> Result<Self> {
        let hash = Sha256::digest(seed.as_bytes());
        let signing_key = SigningKey::from_bytes((&hash).into())
            .map_err(|e| anyhow::anyhow!("invalid seed: {e}"))?;
        Ok(Self { signing_key })
    }
}

impl ContextSigner for EthereumSecp256k1Signer {
    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>> {
        let (signature, recovery_id): (k256::ecdsa::Signature, RecoveryId) = self
            .signing_key
            .sign_prehash(digest)
            .map_err(|e| anyhow::anyhow!("ethereum secp256k1 sign_prehash failed: {e}"))?;

        // 65-byte signature: 32 bytes r + 32 bytes s + 1 byte v
        let mut sig_bytes = signature.to_bytes().to_vec();
        sig_bytes.push(recovery_id.to_byte());
        Ok(sig_bytes)
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        // Uncompressed public key (65 bytes) — standard for Ethereum address derivation
        self.signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    fn algorithm(&self) -> &str {
        "ethereum-secp256k1"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{VerifyingKey, Signature, RecoveryId};

    #[test]
    fn signature_is_65_bytes() {
        let signer = EthereumSecp256k1Signer::from_seed("test-seed").unwrap();
        let digest = Sha256::digest(b"data");
        let sig = signer.sign_digest(&digest).unwrap();
        assert_eq!(sig.len(), 65, "ethereum signature should be 65 bytes (r+s+v)");
    }

    #[test]
    fn recovery_id_valid() {
        let signer = EthereumSecp256k1Signer::from_seed("test-seed").unwrap();
        let digest = Sha256::digest(b"data");
        let sig = signer.sign_digest(&digest).unwrap();
        let v = sig[64];
        assert!(v <= 1, "recovery ID should be 0 or 1, got {v}");
    }

    #[test]
    fn deterministic_signing() {
        let signer = EthereumSecp256k1Signer::from_seed("test-seed").unwrap();
        let digest = Sha256::digest(b"hello");
        let sig1 = signer.sign_digest(&digest).unwrap();
        let sig2 = signer.sign_digest(&digest).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn public_key_is_65_bytes_uncompressed() {
        let signer = EthereumSecp256k1Signer::from_seed("test-seed").unwrap();
        let pk = signer.public_key_bytes();
        assert_eq!(pk.len(), 65, "uncompressed public key should be 65 bytes");
        assert_eq!(pk[0], 0x04, "uncompressed key should start with 0x04");
    }

    #[test]
    fn signature_recovers_correct_public_key() {
        let signer = EthereumSecp256k1Signer::from_seed("recovery-test").unwrap();
        let digest = Sha256::digest(b"recover me");
        let sig_bytes = signer.sign_digest(&digest).unwrap();

        let signature = Signature::from_slice(&sig_bytes[..64]).unwrap();
        let recovery_id = RecoveryId::from_byte(sig_bytes[64]).unwrap();

        let recovered_key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
            .unwrap();

        let expected_pk = signer.signing_key.verifying_key();
        assert_eq!(
            recovered_key.to_encoded_point(false),
            expected_pk.to_encoded_point(false),
            "recovered public key should match signer's public key"
        );
    }

    #[test]
    fn algorithm_is_ethereum_secp256k1() {
        let signer = EthereumSecp256k1Signer::from_seed("test").unwrap();
        assert_eq!(signer.algorithm(), "ethereum-secp256k1");
    }
}
