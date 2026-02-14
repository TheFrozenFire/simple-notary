use futures::{AsyncReadExt, AsyncWriteExt};
use tlsn::{
    Session,
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{TlsCommitConfig, mpc::MpcTlsConfig},
        verifier::VerifierConfig,
    },
    connection::ServerName,
    hash::HashAlgId,
    prover::Prover,
    transcript::{Direction, TranscriptCommitConfig, TranscriptCommitmentKind},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture::bind;
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tokio_util::compat::TokioAsyncReadCompatExt;

use simple_notary::notarize;

const MAX_SENT_DATA: usize = 1 << 12;
const MAX_SENT_RECORDS: usize = 4;
const MAX_RECV_DATA: usize = 1 << 14;
const MAX_RECV_RECORDS: usize = 6;

fn test_verifier_config() -> VerifierConfig {
    VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        })
        .build()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_notarization_flow() {
    let (socket_0, socket_1) = tokio::io::duplex(2 << 23);

    let mut session_p = Session::new(socket_0.compat());
    let prover = session_p
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap();

    let (session_p_driver, session_p_handle) = session_p.split();
    tokio::spawn(session_p_driver);

    let verifier_config = test_verifier_config();

    let (prover_result, verifier_result) = tokio::join!(
        run_prover(prover),
        notarize(socket_1.compat(), verifier_config),
    );

    session_p_handle.close();

    let _transcript = prover_result;
    let (partial_transcript, _io) = verifier_result.expect("notarize should succeed");

    assert!(partial_transcript.len_sent() > 0, "should have sent data");
    assert!(
        partial_transcript.len_received() > 0,
        "should have received data"
    );
}

async fn run_prover(prover: Prover) {
    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);
    let server_task = tokio::spawn(bind(server_socket.compat()));

    let prover = prover
        .commit(
            TlsCommitConfig::builder()
                .protocol(
                    MpcTlsConfig::builder()
                        .max_sent_data(MAX_SENT_DATA)
                        .max_sent_records(MAX_SENT_RECORDS)
                        .max_recv_data(MAX_RECV_DATA)
                        .max_recv_records_online(MAX_RECV_RECORDS)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .await
        .unwrap();

    let (mut tls_connection, prover_fut) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()
                .unwrap(),
            client_socket.compat(),
        )
        .await
        .unwrap();
    let prover_task = tokio::spawn(prover_fut);

    tls_connection
        .write_all(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    tls_connection.close().await.unwrap();

    let mut response = vec![0u8; 1024];
    tls_connection.read_to_end(&mut response).await.unwrap();

    let _ = server_task.await.unwrap();

    let mut prover = prover_task.await.unwrap().unwrap();
    let sent_tx_len = prover.transcript().sent().len();
    let recv_tx_len = prover.transcript().received().len();

    let mut commit_builder = TranscriptCommitConfig::builder(prover.transcript());
    let kind = TranscriptCommitmentKind::Hash {
        alg: HashAlgId::SHA256,
    };
    commit_builder
        .commit_with_kind(&(0..sent_tx_len), Direction::Sent, kind)
        .unwrap();
    commit_builder
        .commit_with_kind(&(0..recv_tx_len), Direction::Received, kind)
        .unwrap();

    let mut prove_builder = ProveConfig::builder(prover.transcript());
    prove_builder.server_identity();
    prove_builder.reveal_sent(&(0..sent_tx_len)).unwrap();
    prove_builder.reveal_recv(&(0..recv_tx_len)).unwrap();
    prove_builder.transcript_commit(commit_builder.build().unwrap());

    let config = prove_builder.build().unwrap();
    prover.prove(&config).await.unwrap();
    prover.close().await.unwrap();
}
