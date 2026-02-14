use anyhow::{Context, Result, bail};
use futures::io::{AsyncRead, AsyncWrite};
use http_transcript_context::http::HttpContext;

use super::protocol::{NotaryMessage, ProverMessage, read_message, write_message};
use super::signer::ContextSigner;
use super::subset::is_json_subset;

/// Runs the two-phase signing exchange over a byte stream.
///
/// 1. Sends the canonical JSON context to the prover.
/// 2. Waits for a `SignRequest` (sign full context) or `SignFiltered` (sign a subset).
/// 3. Validates and signs the data, then sends the `Signed` response.
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

    let prover_msg: ProverMessage = read_message(&mut io)
        .await
        .context("reading prover message")?;

    let data_to_sign = match prover_msg {
        ProverMessage::SignRequest => canonical_json,
        ProverMessage::SignFiltered { data } => {
            let original: serde_json::Value = serde_json::from_str(&canonical_json)
                .context("parsing original context as JSON Value")?;
            let filtered: serde_json::Value = serde_json::from_str(&data)
                .context("parsing filtered context as JSON Value")?;

            if !is_json_subset(&filtered, &original) {
                bail!("filtered context is not a valid subset of the original context");
            }

            // Re-canonicalize: serde_json::Map uses BTreeMap so key order is deterministic.
            serde_json::to_string(&filtered)
                .context("re-canonicalizing filtered context")?
        }
    };

    let signature_bytes = signer
        .sign(data_to_sign.as_bytes())
        .context("signing context")?;

    write_message(
        &mut io,
        &NotaryMessage::Signed {
            data: data_to_sign,
            signature: hex::encode(&signature_bytes),
            public_key: hex::encode(signer.public_key_bytes()),
            algorithm: signer.algorithm().to_string(),
        },
    )
    .await
    .context("sending Signed message")?;

    Ok(())
}
