use clap::Parser;
use simple_notary_client::run;

#[derive(Parser)]
struct Args {
    #[clap(long, default_value = "127.0.0.1")]
    host: Option<String>,
    #[clap(long, default_value = "3000")]
    port: Option<u16>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    println!("Running");
    run(args.host.unwrap(), args.port.unwrap()).await.unwrap();
}
