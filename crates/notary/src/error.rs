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
