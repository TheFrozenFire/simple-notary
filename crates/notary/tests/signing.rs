use tokio::io::duplex;
use tokio_util::compat::TokioAsyncReadCompatExt;

use rangeset::set::RangeSet;
use simple_notary::signing::{
    NotaryMessage, ProverMessage, Secp256k1Signer, EthereumSecp256k1Signer,
    read_message, run_signing_exchange, write_message, is_json_subset,
};
use simple_notary::encoding::{JsonEncoder, AbiEncoder, Eip712Encoder};
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

// ── JSON encoder tests ───────────────────────────────────────────────

#[tokio::test]
async fn full_signing_exchange() {
    let (prover_io, notary_io) = duplex(8192);
    let signer = Secp256k1Signer::from_seed("test-seed").unwrap();
    let encoder = JsonEncoder;

    let notary_task = tokio::spawn(async move {
        run_signing_exchange(notary_io.compat(), test_context(), &signer, &encoder)
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
            format,
            signature,
            public_key,
            algorithm,
        } => {
            // Compare as Values since key ordering may differ (struct vs BTreeMap)
            let signed_value: serde_json::Value = serde_json::from_str(&data).unwrap();
            let context_value: serde_json::Value = serde_json::from_str(&context_data).unwrap();
            assert_eq!(signed_value, context_value, "signed data should match context data");
            assert_eq!(format, "json");
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
    let encoder = JsonEncoder;

    let notary_task = tokio::spawn(async move {
        run_signing_exchange(notary_io.compat(), context, &signer, &encoder)
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
            // Compare as Values since key ordering may differ (struct vs BTreeMap canonical)
            let signed_value: serde_json::Value = serde_json::from_str(&data).unwrap();
            let expected_value: serde_json::Value = serde_json::from_str(&expected_json).unwrap();
            assert_eq!(signed_value, expected_value, "signed data should be canonical JSON");
        }
        other => panic!("expected Signed, got {:?}", other),
    }

    notary_task.await.unwrap();
}

#[tokio::test]
async fn selective_disclosure_filtered_signing() {
    let (prover_io, notary_io) = duplex(8192);
    let signer = Secp256k1Signer::from_seed("filtered-test").unwrap();
    let encoder = JsonEncoder;

    let notary_task = tokio::spawn(async move {
        run_signing_exchange(notary_io.compat(), test_context(), &signer, &encoder)
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

    if let Some(headers) = context_value
        .pointer_mut("/responses/0/headers")
        .and_then(|v| v.as_array_mut())
    {
        if !headers.is_empty() {
            headers[0] = serde_json::Value::Null;
        }
    }

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

    // 4. Read Signed message
    let msg: NotaryMessage = read_message(&mut prover_io).await.unwrap();
    match msg {
        NotaryMessage::Signed {
            data,
            signature,
            algorithm,
            ..
        } => {
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
    let encoder = JsonEncoder;

    let notary_task = tokio::spawn(async move {
        let result = run_signing_exchange(notary_io.compat(), test_context(), &signer, &encoder).await;
        assert!(result.is_err(), "exchange should fail for invalid subset");
    });

    let mut prover_io = prover_io.compat();

    let msg: NotaryMessage = read_message(&mut prover_io).await.unwrap();
    let context_data = match msg {
        NotaryMessage::Context { data } => data,
        other => panic!("expected Context, got {:?}", other),
    };

    let mut context_value: serde_json::Value = serde_json::from_str(&context_data).unwrap();
    *context_value
        .pointer_mut("/requests/0/method")
        .expect("method field should exist") = serde_json::Value::String("POST".to_string());

    let tampered_json = serde_json::to_string(&context_value).unwrap();

    write_message(
        &mut prover_io,
        &ProverMessage::SignFiltered {
            data: tampered_json,
        },
    )
    .await
    .unwrap();

    notary_task.await.unwrap();
}

// ── ABI encoder tests ────────────────────────────────────────────────

#[tokio::test]
async fn abi_signing_exchange() {
    let (prover_io, notary_io) = duplex(16384);
    let signer = Secp256k1Signer::from_seed("abi-test").unwrap();
    let encoder = AbiEncoder;

    let notary_task = tokio::spawn(async move {
        run_signing_exchange(notary_io.compat(), test_context(), &signer, &encoder)
            .await
            .unwrap();
    });

    let mut prover_io = prover_io.compat();

    // 1. Context is always JSON (for prover review)
    let msg: NotaryMessage = read_message(&mut prover_io).await.unwrap();
    let _context_data = match msg {
        NotaryMessage::Context { data } => {
            // Verify it's valid JSON
            let _: serde_json::Value = serde_json::from_str(&data).unwrap();
            data
        }
        other => panic!("expected Context, got {:?}", other),
    };

    // 2. Request signing
    write_message(&mut prover_io, &ProverMessage::SignRequest)
        .await
        .unwrap();

    // 3. Signed response should be ABI-encoded
    let msg: NotaryMessage = read_message(&mut prover_io).await.unwrap();
    match msg {
        NotaryMessage::Signed {
            data,
            format,
            signature,
            algorithm,
            ..
        } => {
            assert_eq!(format, "abi");
            assert_eq!(algorithm, "secp256k1");

            // Data should be hex-encoded ABI bytes
            let abi_bytes = hex::decode(&data).unwrap();
            assert!(!abi_bytes.is_empty());

            let sig_bytes = hex::decode(&signature).unwrap();
            assert_eq!(sig_bytes.len(), 64);
        }
        other => panic!("expected Signed, got {:?}", other),
    }

    notary_task.await.unwrap();
}

#[tokio::test]
async fn abi_selective_disclosure() {
    let (prover_io, notary_io) = duplex(16384);
    let signer = Secp256k1Signer::from_seed("abi-filtered").unwrap();
    let encoder = AbiEncoder;

    let notary_task = tokio::spawn(async move {
        run_signing_exchange(notary_io.compat(), test_context(), &signer, &encoder)
            .await
            .unwrap();
    });

    let mut prover_io = prover_io.compat();

    let msg: NotaryMessage = read_message(&mut prover_io).await.unwrap();
    let context_data = match msg {
        NotaryMessage::Context { data } => data,
        other => panic!("expected Context, got {:?}", other),
    };

    // Filter: null-out the first response
    let mut context_value: serde_json::Value = serde_json::from_str(&context_data).unwrap();
    if let Some(responses) = context_value.get_mut("responses").and_then(|v| v.as_array_mut()) {
        if !responses.is_empty() {
            responses[0] = serde_json::Value::Null;
        }
    }

    let filtered_json = serde_json::to_string(&context_value).unwrap();
    write_message(
        &mut prover_io,
        &ProverMessage::SignFiltered { data: filtered_json },
    )
    .await
    .unwrap();

    let msg: NotaryMessage = read_message(&mut prover_io).await.unwrap();
    match msg {
        NotaryMessage::Signed { format, data, .. } => {
            assert_eq!(format, "abi");
            let abi_bytes = hex::decode(&data).unwrap();
            assert!(!abi_bytes.is_empty());
        }
        other => panic!("expected Signed, got {:?}", other),
    }

    notary_task.await.unwrap();
}

// ── EIP-712 encoder tests ────────────────────────────────────────────

#[tokio::test]
async fn eip712_signing_exchange() {
    let (prover_io, notary_io) = duplex(16384);
    let signer = Secp256k1Signer::from_seed("eip712-test").unwrap();
    let encoder = Eip712Encoder::new(
        "SimpleNotary".to_string(),
        "1".to_string(),
        1,
        [0u8; 20],
    );

    let notary_task = tokio::spawn(async move {
        run_signing_exchange(notary_io.compat(), test_context(), &signer, &encoder)
            .await
            .unwrap();
    });

    let mut prover_io = prover_io.compat();

    let msg: NotaryMessage = read_message(&mut prover_io).await.unwrap();
    match msg {
        NotaryMessage::Context { .. } => {}
        other => panic!("expected Context, got {:?}", other),
    }

    write_message(&mut prover_io, &ProverMessage::SignRequest)
        .await
        .unwrap();

    let msg: NotaryMessage = read_message(&mut prover_io).await.unwrap();
    match msg {
        NotaryMessage::Signed {
            format,
            data,
            signature,
            algorithm,
            ..
        } => {
            assert_eq!(format, "eip712");
            assert_eq!(algorithm, "secp256k1");

            // Data is hex-encoded ABI bytes (same struct as ABI encoder)
            let abi_bytes = hex::decode(&data).unwrap();
            assert!(!abi_bytes.is_empty());

            let sig_bytes = hex::decode(&signature).unwrap();
            assert_eq!(sig_bytes.len(), 64);
        }
        other => panic!("expected Signed, got {:?}", other),
    }

    notary_task.await.unwrap();
}

// ── Ethereum signer tests ────────────────────────────────────────────

#[tokio::test]
async fn ethereum_signer_produces_recoverable_signature() {
    let (prover_io, notary_io) = duplex(16384);
    let signer = EthereumSecp256k1Signer::from_seed("eth-test").unwrap();
    let encoder = AbiEncoder;

    let notary_task = tokio::spawn(async move {
        run_signing_exchange(notary_io.compat(), test_context(), &signer, &encoder)
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
        NotaryMessage::Signed {
            signature,
            public_key,
            algorithm,
            ..
        } => {
            assert_eq!(algorithm, "ethereum-secp256k1");

            let sig_bytes = hex::decode(&signature).unwrap();
            assert_eq!(sig_bytes.len(), 65, "ethereum signature should be 65 bytes (r+s+v)");

            let pk_bytes = hex::decode(&public_key).unwrap();
            assert_eq!(pk_bytes.len(), 65, "uncompressed public key should be 65 bytes");
            assert_eq!(pk_bytes[0], 0x04, "uncompressed key should start with 0x04");

            // Verify recovery ID is valid
            let v = sig_bytes[64];
            assert!(v <= 1, "recovery ID should be 0 or 1, got {v}");
        }
        other => panic!("expected Signed, got {:?}", other),
    }

    notary_task.await.unwrap();
}

#[tokio::test]
async fn ethereum_signer_with_eip712() {
    let (prover_io, notary_io) = duplex(16384);
    let signer = EthereumSecp256k1Signer::from_seed("eth-eip712").unwrap();
    let encoder = Eip712Encoder::new(
        "SimpleNotary".to_string(),
        "1".to_string(),
        1,
        [0u8; 20],
    );

    let notary_task = tokio::spawn(async move {
        run_signing_exchange(notary_io.compat(), test_context(), &signer, &encoder)
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
        NotaryMessage::Signed {
            format,
            signature,
            algorithm,
            ..
        } => {
            assert_eq!(format, "eip712");
            assert_eq!(algorithm, "ethereum-secp256k1");

            let sig_bytes = hex::decode(&signature).unwrap();
            assert_eq!(sig_bytes.len(), 65, "ethereum sig should be 65 bytes");
        }
        other => panic!("expected Signed, got {:?}", other),
    }

    notary_task.await.unwrap();
}
