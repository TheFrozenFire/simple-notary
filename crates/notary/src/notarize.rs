use anyhow::Result;
use futures::io::{AsyncRead, AsyncWrite};

use tlsn::{
    config::ProtocolConfigValidator,
    verifier::{Verifier, VerifierConfig, VerifierOutput, VerifyConfig, state::Committed},
};

use http_transcript_context::transcript::PartialTranscript;

pub async fn notarize<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(socket: T) -> Result<PartialTranscript> {
    let validator_config = ProtocolConfigValidator::builder()
        .build()?;

    let verifier_config = VerifierConfig::builder()
        .protocol_config_validator(validator_config)
        .build()?;
    
    let verifier = Verifier::new(verifier_config);

    let mut verifier = verifier.setup(socket).await?.run().await?;

    let VerifierOutput {
        server_name,
        transcript: tlsn_transcript,
        ..
    } = verifier.verify( &VerifyConfig::default()).await?;

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