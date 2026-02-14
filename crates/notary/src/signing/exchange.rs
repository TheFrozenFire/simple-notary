use anyhow::{Context, Result};
use futures::io::{AsyncRead, AsyncWrite};
use http_transcript_context::http::HttpContext;

use super::protocol::{NotaryMessage, ProverMessage, read_message, write_message};
use super::signer::ContextSigner;

/// Runs the two-phase signing exchange over a byte stream.
///
/// 1. Sends the canonical JSON context to the prover.
/// 2. Waits for a `SignRequest`.
/// 3. Signs the canonical bytes and sends the `Signed` response.
pub async fn run_signing_exchange<T>(
    mut io: T,
    context: HttpContext,
    signer: &dyn ContextSigner,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let canonical_json =
        serde_json::to_string(&context).context("serializing context to canonical JSON")?;

    write_message(&mut io, &NotaryMessage::Context {
        data: canonical_json.clone(),
    })
    .await
    .context("sending Context message")?;

    let _: ProverMessage = read_message(&mut io)
        .await
        .context("reading SignRequest")?;

    let signature_bytes = signer
        .sign(canonical_json.as_bytes())
        .context("signing context")?;

    write_message(
        &mut io,
        &NotaryMessage::Signed {
            data: canonical_json,
            signature: hex::encode(&signature_bytes),
            public_key: hex::encode(signer.public_key_bytes()),
            algorithm: signer.algorithm().to_string(),
        },
    )
    .await
    .context("sending Signed message")?;

    Ok(())
}
