use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use crate::server::axum_websocket::{WebSocketUpgrade, header_eq};

/// A wrapper enum to facilitate extracting TCP connection for either WebSocket
/// or TCP clients, so that we can use a single endpoint and handler for
/// notarization for both types of clients
pub enum ProtocolUpgrade {
    Tcp(TcpUpgrade),
    Ws(WebSocketUpgrade),
}

impl<S> FromRequestParts<S> for ProtocolUpgrade
where
    S: Send + Sync,
{
    type Rejection = axum::Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract tcp connection for websocket client
        if header_eq(&parts.headers, header::UPGRADE, "websocket") {
            let extractor = WebSocketUpgrade::from_request_parts(parts, state)
                .await
                .map_err(|err| NotaryServerError::BadProverRequest(err.to_string()))?;
            Ok(Self::Ws(extractor))
        // Extract tcp connection for tcp client
        } else if header_eq(&parts.headers, header::UPGRADE, "tcp") {
            let extractor = TcpUpgrade::from_request_parts(parts, state)
                .await
                .map_err(|err| NotaryServerError::BadProverRequest(err.to_string()))?;
            Ok(Self::Tcp(extractor))
        } else {
            Err(NotaryServerError::BadProverRequest(
                "Upgrade header is not set for client".to_string(),
            ))
        }
    }
}