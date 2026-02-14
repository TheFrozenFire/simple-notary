use std::sync::Arc;

use clap::{Parser, ValueEnum};
use simple_notary::{ContextSigner, RsaSigner, Secp256k1Signer, run};

#[derive(Debug, Clone, ValueEnum)]
enum SigningAlgorithm {
    Secp256k1,
    Rsa,
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
        };
        signer
    });

    println!("Running");
    run(args.host.unwrap(), args.port.unwrap(), signer)
        .await
        .unwrap();
}
