use anyhow::Result;
use futures::io::{AsyncRead, AsyncWrite};

use tlsn::{
    Session,
    config::verifier::VerifierConfig,
    verifier::VerifierOutput,
};

use http_transcript_context::transcript::PartialTranscript;

/// Runs the TLSNotary verifier protocol over the given I/O stream,
/// returning the verified partial transcript.
///
/// After completion, the underlying I/O is reclaimed from the session
/// and returned alongside the transcript so the caller can continue
/// using the connection (e.g. to send results back).
pub async fn notarize<T>(io: T, verifier_config: VerifierConfig) -> Result<(PartialTranscript, T)>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let session = Session::new(io);
    let (driver, mut handle) = session.split();

    let driver_task = tokio::spawn(driver);

    let verifier = handle.new_verifier(verifier_config)?;

    // Receive prover's config and accept it.
    let verifier = verifier.commit().await?;
    let verifier = verifier.accept().await?;

    // Run MPC-TLS to completion.
    let verifier = verifier.run().await?;

    // Receive and accept the prove request.
    let verifier = verifier.verify().await?;
    let (
        VerifierOutput {
            server_name,
            transcript: tlsn_transcript,
            ..
        },
        verifier,
    ) = verifier.accept().await?;

    verifier.close().await?;

    // Close session and reclaim the I/O.
    handle.close();
    let io = driver_task.await??;

    let _server_name = server_name.unwrap();
    let tlsn_transcript = tlsn_transcript.unwrap();

    let transcript = PartialTranscript::new(
        tlsn_transcript.sent_unsafe().to_vec(),
        tlsn_transcript.received_unsafe().to_vec(),
        tlsn_transcript.sent_authed().clone(),
        tlsn_transcript.received_authed().clone(),
    );

    Ok((transcript, io))
}
