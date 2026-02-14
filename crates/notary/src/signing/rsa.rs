use anyhow::{Context, Result};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::signature::{Signer, SignatureEncoding};
use rsa::RsaPrivateKey;
use sha2::{Sha256, Digest};

use super::signer::ContextSigner;

const RSA_KEY_BITS: usize = 2048;

/// RSA PKCS#1 v1.5 signer with SHA-256 digest.
///
/// Created from a seed string — the SHA-256 hash of the seed
/// seeds a deterministic CSPRNG used for RSA key generation.
pub struct RsaSigner {
    signing_key: SigningKey<Sha256>,
    private_key: RsaPrivateKey,
}

impl RsaSigner {
    pub fn from_seed(seed: &str) -> Result<Self> {
        let hash = Sha256::digest(seed.as_bytes());
        let mut rng = ChaCha20Rng::from_seed(hash.into());
        let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS)
            .context("generating RSA key from seed")?;
        let signing_key = SigningKey::<Sha256>::new(private_key.clone());
        Ok(Self { signing_key, private_key })
    }
}

impl ContextSigner for RsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signature = self.signing_key.sign(data);
        Ok(signature.to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.private_key
            .to_public_key()
            .to_public_key_der()
            .expect("encoding RSA public key to DER")
            .into_vec()
    }

    fn algorithm(&self) -> &str {
        "rsa-pkcs1v15-sha256"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;

    fn test_signer() -> RsaSigner {
        RsaSigner::from_seed("test-seed").unwrap()
    }

    #[test]
    fn deterministic_key_generation() {
        let signer_a = RsaSigner::from_seed("test-seed").unwrap();
        let signer_b = RsaSigner::from_seed("test-seed").unwrap();
        assert_eq!(signer_a.public_key_bytes(), signer_b.public_key_bytes());
    }

    #[test]
    fn deterministic_signing() {
        let signer = test_signer();
        let sig1 = signer.sign(b"hello").unwrap();
        let sig2 = signer.sign(b"hello").unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        let signer_a = RsaSigner::from_seed("seed-a").unwrap();
        let signer_b = RsaSigner::from_seed("seed-b").unwrap();
        assert_ne!(signer_a.public_key_bytes(), signer_b.public_key_bytes());
    }

    #[test]
    fn signature_is_256_bytes() {
        let signer = test_signer();
        let sig = signer.sign(b"data").unwrap();
        assert_eq!(sig.len(), RSA_KEY_BITS / 8);
    }

    #[test]
    fn algorithm_is_rsa_pkcs1v15_sha256() {
        let signer = test_signer();
        assert_eq!(signer.algorithm(), "rsa-pkcs1v15-sha256");
    }

    #[test]
    fn signature_verifies() {
        let signer = test_signer();
        let data = b"verify me";
        let sig_bytes = signer.sign(data).unwrap();

        let verifying_key = VerifyingKey::<Sha256>::new(signer.private_key.to_public_key());
        let signature = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()).unwrap();
        verifying_key.verify(data, &signature).unwrap();
    }
}
