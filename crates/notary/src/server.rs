use anyhow::Result;

use axum::{
    Router,
    extract::Query,
    http::StatusCode,
    response::IntoResponse,
    routing::{any, get},
};
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};

use crate::notarize::notarize;
use http_transcript_context::http::HttpContext;
use tlsn::{config::verifier::VerifierConfig, webpki::RootCertStore};
use ws_stream_tungstenite::WsStream;

use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use axum_websocket::{
    WebSocket,
    WebSocketUpgrade,
    header_eq,
};
use crate::error::NotaryServerError;
use futures::io::AsyncWriteExt;

pub fn router() -> Router {
    Router::new()
        .route("/healthcheck", get(|| async move { (StatusCode::OK, "Ok").into_response() }))
        .route("/notarize", any(notarize_handler))
}

pub async fn run(
    host: String,
    port: u16,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(format!("{}:{}", host, port))
        .await
        .unwrap();

    axum::serve(
        listener,
        router().into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotarizationContextFormat {
    Json,
    Binary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotarizationRequestQuery {
    pub context_format: NotarizationContextFormat,
}

async fn notarize_handler(
    protocol_upgrade: ProtocolUpgrade,
    Query(params): Query<NotarizationRequestQuery>,
) -> impl IntoResponse {
    match protocol_upgrade {
        ProtocolUpgrade::Ws(ws) => ws.on_upgrade(move |socket| handle_notarize(socket, params.context_format)),
    }
}

async fn handle_notarize(
    socket: WebSocket,
    context_format: NotarizationContextFormat,
) {
    let (inner, _protocol) = socket.into_inner();
    let ws_stream = WsStream::new(inner);

    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore::empty())
        .build()
        .unwrap();

    // Run the verifier protocol; the session reclaims the I/O when done.
    let (transcript, mut ws_stream) = notarize(ws_stream, verifier_config).await.unwrap();

    let context = HttpContext::builder(transcript).build().unwrap();

    match context_format {
        NotarizationContextFormat::Json => {
            let context_json = serde_json::to_value(context).unwrap();
            ws_stream.write_all(context_json.to_string().as_bytes()).await.unwrap();
        }
        _ => todo!(),
    }
}

/// A wrapper enum to facilitate extracting TCP connection for either WebSocket
/// or TCP clients, so that we can use a single endpoint and handler for
/// notarization for both types of clients
pub enum ProtocolUpgrade {
    Ws(WebSocketUpgrade),
}

impl<S> FromRequestParts<S> for ProtocolUpgrade
where
    S: Send + Sync,
{
    type Rejection = NotaryServerError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract tcp connection for websocket client
        if header_eq(&parts.headers, header::UPGRADE, "websocket") {
            let extractor = WebSocketUpgrade::from_request_parts(parts, state)
                .await
                .map_err(|err| NotaryServerError::BadProverRequest(err.to_string()))?;
            Ok(Self::Ws(extractor))
        } else {
            Err(NotaryServerError::BadProverRequest(
                "Upgrade header is not set for client".to_string(),
            ))
        }
    }
}
