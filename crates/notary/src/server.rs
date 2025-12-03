pub mod protocol_upgrade;
pub mod axum_websocket;

use anyhow::Result;

use axum::{
    Json, Router,
    extract::Request,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{any, get, post},
    extract::{
        ConnectInfo,
    },
};
use std::net::SocketAddr;

use crate::notarize::notarize;
use http_transcript_context::http::HttpContext;
use ws_stream_tungstenite::WsStream;

use crate::server::protocol_upgrade::ProtocolUpgrade;
use crate::server::axum_websocket::{WebSocket, WebSocketUpgrade};

pub async fn run() -> Result<()> {
    let router = Router::new()
        .route("/healthcheck", get(|| async move { (StatusCode::OK, "Ok").into_response() }))
        .route("/notarize", any(notarize_handler));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();

    Ok(())
}

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
        _ => todo!(),
    }
}

async fn handle_notarize(
    mut socket: WebSocket,
    context_format: NotarizationContextFormat,
) -> impl IntoResponse {
    let mut stream = WsStream::new(socket.into_inner());

    let transcript = notarize(stream).await?;

    let context = HttpContext::builder(transcript).build().unwrap();

    match context_format {
        NotarizationContextFormat::Json => {
            let context_json = serde_json::to_value(context).unwrap();
            (StatusCode::OK, Json(context_json)).into_response()
        }
        NotarizationContextFormat::Binary => {
            let context_binary = serde_json::to_value(context).unwrap();
            (StatusCode::OK, Binary(context_binary)).into_response()
        }
    }
}