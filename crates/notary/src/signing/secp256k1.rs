use anyhow::Result;
use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Sha256, Digest};

use super::signer::ContextSigner;

/// ECDSA signer using the secp256k1 curve.
///
/// Created from a seed string — the SHA-256 hash of the seed
/// becomes the 32-byte private key.
pub struct Secp256k1Signer {
    signing_key: SigningKey,
}

impl Secp256k1Signer {
    pub fn from_seed(seed: &str) -> Result<Self> {
        let hash = Sha256::digest(seed.as_bytes());
        let signing_key = SigningKey::from_bytes((&hash).into())
            .map_err(|e| anyhow::anyhow!("invalid seed: {e}"))?;
        Ok(Self { signing_key })
    }
}

impl ContextSigner for Secp256k1Signer {
    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>> {
        let (signature, _): (k256::ecdsa::Signature, _) = self
            .signing_key
            .sign_prehash(digest)
            .map_err(|e| anyhow::anyhow!("secp256k1 sign_prehash failed: {e}"))?;
        Ok(signature.to_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    fn algorithm(&self) -> &str {
        "secp256k1"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_signing() {
        let signer = Secp256k1Signer::from_seed("test-seed").unwrap();
        let digest = Sha256::digest(b"hello");
        let sig1 = signer.sign_digest(&digest).unwrap();
        let sig2 = signer.sign_digest(&digest).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        let signer_a = Secp256k1Signer::from_seed("seed-a").unwrap();
        let signer_b = Secp256k1Signer::from_seed("seed-b").unwrap();
        assert_ne!(signer_a.public_key_bytes(), signer_b.public_key_bytes());
    }

    #[test]
    fn signature_is_64_bytes() {
        let signer = Secp256k1Signer::from_seed("test-seed").unwrap();
        let digest = Sha256::digest(b"data");
        let sig = signer.sign_digest(&digest).unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn public_key_is_33_bytes_compressed() {
        let signer = Secp256k1Signer::from_seed("test-seed").unwrap();
        assert_eq!(signer.public_key_bytes().len(), 33);
    }

    #[test]
    fn algorithm_is_secp256k1() {
        let signer = Secp256k1Signer::from_seed("test-seed").unwrap();
        assert_eq!(signer.algorithm(), "secp256k1");
    }
}
