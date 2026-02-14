use axum::http::StatusCode;
use axum_core::response::{IntoResponse as AxumCoreIntoResponse, Response};
use eyre::Report;
use std::error::Error;

#[derive(Debug, thiserror::Error)]
pub enum NotaryServerError {
    #[error(transparent)]
    Unexpected(#[from] Report),
    #[error("Failed to connect to prover: {0}")]
    Connection(String),
    #[error("Error occurred during notarization: {0}")]
    Notarization(Box<dyn Error + Send + 'static>),
    #[error("Invalid request from prover: {0}")]
    BadProverRequest(String),
    #[error("Unauthorized request from prover: {0}")]
    UnauthorizedProverRequest(String),
    #[error("Failed to read credential signing key: {0}")]
    CredentialSigningKeyError(String),
}

impl From<tlsn::Error> for NotaryServerError {
    fn from(error: tlsn::Error) -> Self {
        Self::Notarization(Box::new(error))
    }
}

/// Trait implementation to convert this error into an axum http response
impl AxumCoreIntoResponse for NotaryServerError {
    fn into_response(self) -> Response {
        match self {
            bad_request_error @ NotaryServerError::BadProverRequest(_) => {
                (StatusCode::BAD_REQUEST, bad_request_error.to_string()).into_response()
            }
            unauthorized_request_error @ NotaryServerError::UnauthorizedProverRequest(_) => (
                StatusCode::UNAUTHORIZED,
                unauthorized_request_error.to_string(),
            )
                .into_response(),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something wrong happened.",
            )
                .into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_prover_request_returns_400() {
        let error = NotaryServerError::BadProverRequest("bad".into());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn unauthorized_prover_request_returns_401() {
        let error = NotaryServerError::UnauthorizedProverRequest("unauth".into());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn connection_error_returns_500() {
        let error = NotaryServerError::Connection("conn failed".into());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn credential_signing_key_error_returns_500() {
        let error = NotaryServerError::CredentialSigningKeyError("key error".into());
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
