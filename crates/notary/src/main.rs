use std::sync::Arc;

use clap::{Parser, ValueEnum};
use simple_notary::{
    ContextSigner, ContextEncoder,
    Secp256k1Signer, RsaSigner, EthereumSecp256k1Signer,
    JsonEncoder, AbiEncoder, Eip712Encoder,
    run,
};

#[derive(Debug, Clone, ValueEnum)]
enum SigningAlgorithm {
    Secp256k1,
    Rsa,
    EthereumSecp256k1,
}

#[derive(Debug, Clone, ValueEnum)]
enum ContextEncoding {
    Json,
    Abi,
    Eip712,
}

#[derive(Parser)]
struct Args {
    #[clap(long, default_value = "127.0.0.1")]
    host: Option<String>,
    #[clap(long, default_value = "3000")]
    port: Option<u16>,
    #[clap(long, env = "SIGNING_KEY_SEED")]
    signing_key_seed: Option<String>,
    #[clap(long, env = "SIGNING_ALGORITHM", default_value = "secp256k1")]
    signing_algorithm: SigningAlgorithm,
    #[clap(long, env = "CONTEXT_ENCODING", default_value = "json")]
    context_encoding: ContextEncoding,

    // EIP-712 domain parameters (only required when encoding=eip712)
    #[clap(long, env = "EIP712_NAME", default_value = "SimpleNotary")]
    eip712_name: String,
    #[clap(long, env = "EIP712_VERSION", default_value = "1")]
    eip712_version: String,
    #[clap(long, env = "EIP712_CHAIN_ID", default_value = "1")]
    eip712_chain_id: u64,
    #[clap(long, env = "EIP712_VERIFYING_CONTRACT", default_value = "0x0000000000000000000000000000000000000000")]
    eip712_verifying_contract: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let signer = args.signing_key_seed.map(|seed| {
        let signer: Arc<dyn ContextSigner> = match args.signing_algorithm {
            SigningAlgorithm::Secp256k1 => Arc::new(
                Secp256k1Signer::from_seed(&seed).expect("failed to create secp256k1 signer"),
            ),
            SigningAlgorithm::Rsa => Arc::new(
                RsaSigner::from_seed(&seed).expect("failed to create RSA signer"),
            ),
            SigningAlgorithm::EthereumSecp256k1 => Arc::new(
                EthereumSecp256k1Signer::from_seed(&seed)
                    .expect("failed to create ethereum secp256k1 signer"),
            ),
        };
        signer
    });

    let encoder: Arc<dyn ContextEncoder> = match args.context_encoding {
        ContextEncoding::Json => Arc::new(JsonEncoder),
        ContextEncoding::Abi => Arc::new(AbiEncoder),
        ContextEncoding::Eip712 => {
            let contract_bytes = parse_hex_address(&args.eip712_verifying_contract)
                .expect("invalid EIP-712 verifying contract address (expected 0x-prefixed 20-byte hex)");
            Arc::new(Eip712Encoder::new(
                args.eip712_name,
                args.eip712_version,
                args.eip712_chain_id,
                contract_bytes,
            ))
        }
    };

    // Validate encoder/signer compatibility
    if let Some(ref signer) = signer {
        let algo = signer.algorithm();
        let enc = encoder.name();
        if algo == "rsa-pkcs1v15-sha256" && enc != "json" {
            panic!(
                "RSA signer is only compatible with JSON encoding (SHA-256 digest). \
                 ABI and EIP-712 encodings use keccak256 digests. \
                 Use --signing-algorithm secp256k1 or ethereum-secp256k1 instead."
            );
        }
    }

    println!("Running");
    run(args.host.unwrap(), args.port.unwrap(), signer, encoder)
        .await
        .unwrap();
}

fn parse_hex_address(s: &str) -> Result<[u8; 20], String> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 20 {
        return Err(format!("expected 20 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
