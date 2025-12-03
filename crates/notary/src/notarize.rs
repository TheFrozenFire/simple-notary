use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::TokioAsyncReadCompatExt;

use tlsn::{
    config::ProtocolConfigValidator,
    verifier::{Verifier, VerifierConfig, VerifierOutput, VerifyConfig},
};

use http_transcript_context::http::HttpContext;
use http_transcript_context::transcript::PartialTranscript;

use tokio::io::AsyncWriteExt;

pub async fn notarize<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(mut socket: T) -> Result<PartialTranscript> {
    let validator_config = ProtocolConfigValidator::builder()
        .build()?;

    let verifier_config = VerifierConfig::builder()
        .protocol_config_validator(validator_config)
        .build()?;
    
    let verifier = Verifier::new(verifier_config);

    let VerifierOutput {
        server_name,
        transcript: tlsn_transcript,
        ..
    } = verifier.verify(socket.compat(), &VerifyConfig::default()).await?;

    let _server_name = server_name.unwrap();
    let tlsn_transcript = tlsn_transcript.unwrap();
    
    let transcript = PartialTranscript::new(
        tlsn_transcript.sent_unsafe().to_vec(),
        tlsn_transcript.received_unsafe().to_vec(),
        tlsn_transcript.sent_authed().clone(),
        tlsn_transcript.received_authed().clone(),
    );

    Ok(transcript)
}