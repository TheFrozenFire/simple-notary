use std::sync::Arc;

use clap::Parser;
use simple_notary::{Secp256k1Signer, run};

#[derive(Parser)]
struct Args {
    #[clap(long, default_value = "127.0.0.1")]
    host: Option<String>,
    #[clap(long, default_value = "3000")]
    port: Option<u16>,
    #[clap(long, env = "SIGNING_KEY_SEED")]
    signing_key_seed: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let signer = args.signing_key_seed.map(|seed| {
        let signer = Secp256k1Signer::from_seed(&seed)
            .expect("failed to create signer from seed");
        Arc::new(signer) as Arc<dyn simple_notary::ContextSigner>
    });

    println!("Running");
    run(args.host.unwrap(), args.port.unwrap(), signer)
        .await
        .unwrap();
}
