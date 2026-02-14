use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use alloy_primitives::{keccak256, U256};
use alloy_sol_types::{SolValue, sol};
use fastembed::{EmbeddingModel, InitOptions, TextEmbedding};

use super::{ContextEncoder, EncodeOptions, EncodedContext, Quantization};

sol! {
    struct EmbeddingAttestation {
        string model;
        uint16 dimensions;
        uint8 quantization;
        bytes embedding;
        uint256 scaleWad;
    }
}

/// Quantization discriminator values matching the Solidity struct.
const QUANT_FLOAT32: u8 = 0;
const QUANT_INT8: u8 = 1;

/// WAD precision (1e18) for int8 scale factor.
const WAD: u128 = 1_000_000_000_000_000_000;

/// Maps user-facing model name to fastembed's `EmbeddingModel` enum.
fn resolve_model(name: &str) -> Option<EmbeddingModel> {
    match name {
        "all-MiniLM-L6-v2" => Some(EmbeddingModel::AllMiniLML6V2),
        "all-MiniLM-L12-v2" => Some(EmbeddingModel::AllMiniLML12V2),
        "nomic-embed-text-v1.5" => Some(EmbeddingModel::NomicEmbedTextV15),
        "bge-small-en-v1.5" => Some(EmbeddingModel::BGESmallENV15),
        _ => None,
    }
}

/// Encodes context as a vector embedding with ABI-encoded attestation and keccak256 digest.
///
/// Uses ONNX-based embedding models via `fastembed`. The prover selects a model
/// from the server's whitelist and an optional quantization format.
pub struct EmbeddingEncoder {
    models: Mutex<HashMap<String, TextEmbedding>>,
    allowed_models: Vec<String>,
    cache_dir: Option<PathBuf>,
}

impl EmbeddingEncoder {
    pub fn new(allowed_models: Vec<String>, cache_dir: Option<PathBuf>) -> Self {
        Self {
            models: Mutex::new(HashMap::new()),
            allowed_models,
            cache_dir,
        }
    }

    /// Run embedding inference on the given text, returning the raw f32 vector.
    fn embed(&self, model_name: &str, text: &str) -> Result<Vec<f32>> {
        let mut models = self.models.lock().map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;

        if !models.contains_key(model_name) {
            let fastembed_model = resolve_model(model_name)
                .ok_or_else(|| anyhow::anyhow!("unknown embedding model: {model_name}"))?;

            let mut opts = InitOptions::new(fastembed_model).with_show_download_progress(false);
            if let Some(ref cache_dir) = self.cache_dir {
                opts = opts.with_cache_dir(cache_dir.clone());
            }

            let model = TextEmbedding::try_new(opts)
                .context("loading embedding model")?;
            models.insert(model_name.to_string(), model);
        }

        let model = models.get(model_name).expect("just inserted");
        let embeddings = model.embed(vec![text], None)
            .context("running embedding inference")?;

        embeddings.into_iter().next()
            .ok_or_else(|| anyhow::anyhow!("embedding returned empty result"))
    }
}

impl ContextEncoder for EmbeddingEncoder {
    fn encode(&self, context: &serde_json::Value, options: &EncodeOptions) -> Result<EncodedContext> {
        let model_name = options.embedding_model.as_deref()
            .unwrap_or_else(|| self.allowed_models.first().map(|s| s.as_str()).unwrap_or("all-MiniLM-L6-v2"));

        if !self.allowed_models.iter().any(|m| m == model_name) {
            bail!("model '{model_name}' is not in the server's allowed list: {:?}", self.allowed_models);
        }

        let quantization = options.quantization.unwrap_or(Quantization::Float32);

        let json_text = serde_json::to_string(context)
            .context("serializing context to JSON for embedding")?;

        let raw_embedding = self.embed(model_name, &json_text)?;
        let dimensions = raw_embedding.len() as u16;

        let (embedding_bytes, quant_flag, scale_wad) = match quantization {
            Quantization::Float32 => {
                let bytes: Vec<u8> = raw_embedding.iter()
                    .flat_map(|f| f.to_be_bytes())
                    .collect();
                (bytes, QUANT_FLOAT32, U256::ZERO)
            }
            Quantization::Int8 => {
                let max_abs = raw_embedding.iter()
                    .map(|f| f.abs())
                    .fold(0.0_f32, f32::max);

                if max_abs == 0.0 {
                    let bytes = vec![0i8 as u8; raw_embedding.len()];
                    return Ok(encode_attestation(model_name, dimensions, QUANT_INT8, bytes, U256::ZERO));
                }

                // scale_wad = max_abs * 1e18
                let scale_wad = U256::from((max_abs as f64 * WAD as f64) as u128);

                let bytes: Vec<u8> = raw_embedding.iter()
                    .map(|f| {
                        let quantized = (f / max_abs * 127.0).round().clamp(-127.0, 127.0) as i8;
                        quantized as u8
                    })
                    .collect();
                (bytes, QUANT_INT8, scale_wad)
            }
        };

        Ok(encode_attestation(model_name, dimensions, quant_flag, embedding_bytes, scale_wad))
    }

    fn name(&self) -> &str {
        "embedding"
    }

    fn available_models(&self) -> Vec<String> {
        self.allowed_models.clone()
    }
}

fn encode_attestation(
    model_name: &str,
    dimensions: u16,
    quantization: u8,
    embedding_bytes: Vec<u8>,
    scale_wad: U256,
) -> EncodedContext {
    let attestation = EmbeddingAttestation {
        model: model_name.to_string(),
        dimensions,
        quantization,
        embedding: embedding_bytes.into(),
        scaleWad: scale_wad,
    };
    let data = attestation.abi_encode();
    let digest = keccak256(&data).to_vec();
    EncodedContext { data, digest }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_encoder() -> EmbeddingEncoder {
        EmbeddingEncoder::new(
            vec!["all-MiniLM-L6-v2".to_string()],
            None,
        )
    }

    #[test]
    fn encode_float32_embedding() {
        let encoder = test_encoder();
        let context = json!({"requests": [{"method": "GET", "target": "/api/data"}], "responses": [{"status": 200}]});
        let options = EncodeOptions {
            embedding_model: Some("all-MiniLM-L6-v2".to_string()),
            quantization: Some(Quantization::Float32),
        };

        let encoded = encoder.encode(&context, &options).unwrap();
        assert!(!encoded.data.is_empty());
        assert_eq!(encoded.digest.len(), 32, "keccak256 digest should be 32 bytes");

        // Decode and verify structure
        let decoded = <EmbeddingAttestation as SolValue>::abi_decode(&encoded.data, true).unwrap();
        assert_eq!(decoded.model, "all-MiniLM-L6-v2");
        assert_eq!(decoded.dimensions, 384);
        assert_eq!(decoded.quantization, QUANT_FLOAT32);
        assert_eq!(decoded.embedding.len(), 384 * 4, "float32: 384 dims * 4 bytes each");
        assert_eq!(decoded.scaleWad, U256::ZERO);
    }

    #[test]
    fn encode_int8_embedding() {
        let encoder = test_encoder();
        let context = json!({"requests": [{"method": "GET", "target": "/api/data"}], "responses": [{"status": 200}]});
        let options = EncodeOptions {
            embedding_model: Some("all-MiniLM-L6-v2".to_string()),
            quantization: Some(Quantization::Int8),
        };

        let encoded = encoder.encode(&context, &options).unwrap();
        let decoded = <EmbeddingAttestation as SolValue>::abi_decode(&encoded.data, true).unwrap();

        assert_eq!(decoded.dimensions, 384);
        assert_eq!(decoded.quantization, QUANT_INT8);
        assert_eq!(decoded.embedding.len(), 384, "int8: 384 dims * 1 byte each");
        assert!(decoded.scaleWad > U256::ZERO, "scale_wad should be set for int8");
    }

    #[test]
    fn rejects_model_not_in_whitelist() {
        let encoder = test_encoder();
        let context = json!({"test": true});
        let options = EncodeOptions {
            embedding_model: Some("unknown-model".to_string()),
            quantization: None,
        };

        let result = encoder.encode(&context, &options);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not in the server's allowed list"));
    }

    #[test]
    fn deterministic_float32() {
        let encoder = test_encoder();
        let context = json!({"key": "value"});
        let options = EncodeOptions {
            embedding_model: Some("all-MiniLM-L6-v2".to_string()),
            quantization: Some(Quantization::Float32),
        };

        let enc1 = encoder.encode(&context, &options).unwrap();
        let enc2 = encoder.encode(&context, &options).unwrap();
        assert_eq!(enc1.data, enc2.data);
        assert_eq!(enc1.digest, enc2.digest);
    }

    #[test]
    fn digest_is_keccak256() {
        let encoder = test_encoder();
        let context = json!({"hello": "world"});
        let options = EncodeOptions {
            embedding_model: Some("all-MiniLM-L6-v2".to_string()),
            quantization: Some(Quantization::Float32),
        };

        let encoded = encoder.encode(&context, &options).unwrap();
        let expected = keccak256(&encoded.data).to_vec();
        assert_eq!(encoded.digest, expected);
    }

    #[test]
    fn name_is_embedding() {
        assert_eq!(test_encoder().name(), "embedding");
    }

    #[test]
    fn available_models_returns_whitelist() {
        let encoder = test_encoder();
        assert_eq!(encoder.available_models(), vec!["all-MiniLM-L6-v2".to_string()]);
    }

    #[test]
    fn default_model_when_none_specified() {
        let encoder = test_encoder();
        let context = json!({"test": true});
        let options = EncodeOptions {
            embedding_model: None,
            quantization: None,
        };

        // Should use first allowed model as default
        let encoded = encoder.encode(&context, &options);
        assert!(encoded.is_ok());
    }
}
