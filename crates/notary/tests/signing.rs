use tokio::io::duplex;
use tokio_util::compat::TokioAsyncReadCompatExt;

use rangeset::set::RangeSet;
use simple_notary::signing::{
    NotaryMessage, ProverMessage, Secp256k1Signer,
    read_message, run_signing_exchange, write_message,
};
use http_transcript_context::http::HttpContext;
use http_transcript_context::transcript::PartialTranscript;

fn test_context() -> HttpContext {
    let sent = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    let received = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".to_vec();
    let sent_authed = RangeSet::from(0..sent.len());
    let recv_authed = RangeSet::from(0..received.len());
    let transcript = PartialTranscript::new(sent, received, sent_authed, recv_authed);
    HttpContext::builder(transcript).build().unwrap()
}

#[tokio::test]
async fn full_signing_exchange() {
    let (prover_io, notary_io) = duplex(8192);
    let signer = Secp256k1Signer::from_seed("test-seed").unwrap();

    let notary_task = tokio::spawn(async move {
        run_signing_exchange(notary_io.compat(), test_context(), &signer)
            .await
            .unwrap();
    });

    let mut prover_io = prover_io.compat();

    // 1. Read Context message
    let msg: NotaryMessage = read_message(&mut prover_io).await.unwrap();
    let context_data = match msg {
        NotaryMessage::Context { data } => data,
        other => panic!("expected Context, got {:?}", other),
    };
    assert!(!context_data.is_empty());

    // 2. Send SignRequest
    write_message(&mut prover_io, &ProverMessage::SignRequest)
        .await
        .unwrap();

    // 3. Read Signed message
    let msg: NotaryMessage = read_message(&mut prover_io).await.unwrap();
    match msg {
        NotaryMessage::Signed {
            data,
            signature,
            public_key,
            algorithm,
        } => {
            assert_eq!(data, context_data, "signed data should match context data");
            assert_eq!(algorithm, "secp256k1");

            let sig_bytes = hex::decode(&signature).unwrap();
            assert_eq!(sig_bytes.len(), 64, "secp256k1 signature should be 64 bytes");

            let pk_bytes = hex::decode(&public_key).unwrap();
            assert_eq!(pk_bytes.len(), 33, "compressed public key should be 33 bytes");
        }
        other => panic!("expected Signed, got {:?}", other),
    }

    notary_task.await.unwrap();
}

#[tokio::test]
async fn signed_data_matches_canonical_serialization() {
    let (prover_io, notary_io) = duplex(8192);
    let context = test_context();
    let expected_json = serde_json::to_string(&context).unwrap();
    let signer = Secp256k1Signer::from_seed("canonical-test").unwrap();

    let notary_task = tokio::spawn(async move {
        run_signing_exchange(notary_io.compat(), context, &signer)
            .await
            .unwrap();
    });

    let mut prover_io = prover_io.compat();

    let _: NotaryMessage = read_message(&mut prover_io).await.unwrap();
    write_message(&mut prover_io, &ProverMessage::SignRequest)
        .await
        .unwrap();

    let msg: NotaryMessage = read_message(&mut prover_io).await.unwrap();
    match msg {
        NotaryMessage::Signed { data, .. } => {
            assert_eq!(data, expected_json, "signed data should be canonical JSON");
        }
        other => panic!("expected Signed, got {:?}", other),
    }

    notary_task.await.unwrap();
}
