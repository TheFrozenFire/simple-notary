use tokio::io::duplex;
use tokio_util::compat::TokioAsyncReadCompatExt;

use rangeset::set::RangeSet;
use simple_notary::signing::{
    NotaryMessage, ProverMessage, Secp256k1Signer,
    read_message, run_signing_exchange, write_message, is_json_subset,
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

#[tokio::test]
async fn selective_disclosure_filtered_signing() {
    let (prover_io, notary_io) = duplex(8192);
    let signer = Secp256k1Signer::from_seed("filtered-test").unwrap();

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

    // 2. Filter the context: null-out a response header, remove the response body key
    let mut context_value: serde_json::Value = serde_json::from_str(&context_data).unwrap();

    // Null-replace a response header (structure is requests/responses arrays)
    if let Some(headers) = context_value
        .pointer_mut("/responses/0/headers")
        .and_then(|v| v.as_array_mut())
    {
        if !headers.is_empty() {
            headers[0] = serde_json::Value::Null;
        }
    }

    // Remove the response body key if it exists
    if let Some(response) = context_value
        .pointer_mut("/responses/0")
        .and_then(|v| v.as_object_mut())
    {
        response.remove("body");
    }

    let filtered_json = serde_json::to_string(&context_value).unwrap();

    // 3. Send SignFiltered
    write_message(
        &mut prover_io,
        &ProverMessage::SignFiltered {
            data: filtered_json.clone(),
        },
    )
    .await
    .unwrap();

    // 4. Read Signed message — should succeed with filtered data
    let msg: NotaryMessage = read_message(&mut prover_io).await.unwrap();
    match msg {
        NotaryMessage::Signed {
            data,
            signature,
            algorithm,
            ..
        } => {
            // The signed data should be the re-canonicalized filtered value
            let signed_value: serde_json::Value = serde_json::from_str(&data).unwrap();
            assert!(is_json_subset(&signed_value, &serde_json::from_str(&context_data).unwrap()));
            assert!(!signature.is_empty());
            assert_eq!(algorithm, "secp256k1");
        }
        other => panic!("expected Signed, got {:?}", other),
    }

    notary_task.await.unwrap();
}

#[tokio::test]
async fn selective_disclosure_rejects_modified_scalar() {
    let (prover_io, notary_io) = duplex(8192);
    let signer = Secp256k1Signer::from_seed("reject-test").unwrap();

    let notary_task = tokio::spawn(async move {
        let result = run_signing_exchange(notary_io.compat(), test_context(), &signer).await;
        assert!(result.is_err(), "exchange should fail for invalid subset");
    });

    let mut prover_io = prover_io.compat();

    // 1. Read Context message
    let msg: NotaryMessage = read_message(&mut prover_io).await.unwrap();
    let context_data = match msg {
        NotaryMessage::Context { data } => data,
        other => panic!("expected Context, got {:?}", other),
    };

    // 2. Modify a scalar value — change the request method
    let mut context_value: serde_json::Value = serde_json::from_str(&context_data).unwrap();
    *context_value
        .pointer_mut("/requests/0/method")
        .expect("method field should exist") = serde_json::Value::String("POST".to_string());

    let tampered_json = serde_json::to_string(&context_value).unwrap();

    // 3. Send SignFiltered with tampered data
    write_message(
        &mut prover_io,
        &ProverMessage::SignFiltered {
            data: tampered_json,
        },
    )
    .await
    .unwrap();

    // The notary task should complete with an error
    notary_task.await.unwrap();
}
