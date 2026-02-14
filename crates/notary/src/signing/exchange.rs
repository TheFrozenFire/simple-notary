use anyhow::{Context, Result, bail};
use futures::io::{AsyncRead, AsyncWrite};
use http_transcript_context::http::HttpContext;

use crate::encoding::ContextEncoder;
use super::protocol::{NotaryMessage, ProverMessage, read_message, write_message};
use super::signer::ContextSigner;
use super::subset::is_json_subset;

/// Runs the two-phase signing exchange over a byte stream.
///
/// 1. Sends the canonical JSON context to the prover (always JSON for review).
/// 2. Waits for a `SignRequest` (sign full context) or `SignFiltered` (sign a subset).
/// 3. Encodes the data using the encoder, signs the digest, sends the `Signed` response.
pub async fn run_signing_exchange<T>(
    mut io: T,
    context: HttpContext,
    signer: &dyn ContextSigner,
    encoder: &dyn ContextEncoder,
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

    let value_to_encode: serde_json::Value = match prover_msg {
        ProverMessage::SignRequest => {
            serde_json::from_str(&canonical_json)
                .context("parsing canonical JSON as Value")?
        }
        ProverMessage::SignFiltered { data } => {
            let original: serde_json::Value = serde_json::from_str(&canonical_json)
                .context("parsing original context as JSON Value")?;
            let filtered: serde_json::Value = serde_json::from_str(&data)
                .context("parsing filtered context as JSON Value")?;

            if !is_json_subset(&filtered, &original) {
                bail!("filtered context is not a valid subset of the original context");
            }

            filtered
        }
    };

    let encoded = encoder
        .encode(&value_to_encode)
        .context("encoding context")?;

    let signature_bytes = signer
        .sign_digest(&encoded.digest)
        .context("signing context digest")?;

    // For JSON format, data is the JSON string; for binary formats, data is hex-encoded bytes.
    let data_str = match encoder.name() {
        "json" => String::from_utf8(encoded.data)
            .context("encoded JSON data is not valid UTF-8")?,
        _ => hex::encode(&encoded.data),
    };

    write_message(
        &mut io,
        &NotaryMessage::Signed {
            data: data_str,
            format: encoder.name().to_string(),
            signature: hex::encode(&signature_bytes),
            public_key: hex::encode(signer.public_key_bytes()),
            algorithm: signer.algorithm().to_string(),
        },
    )
    .await
    .context("sending Signed message")?;

    Ok(())
}
