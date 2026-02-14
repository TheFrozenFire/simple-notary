use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use simple_notary::{AppState, router};
use tower::ServiceExt;

fn test_state() -> AppState {
    AppState { signer: None }
}

#[tokio::test]
async fn healthcheck_returns_200() {
    let app = router(test_state());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/healthcheck")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"Ok");
}

#[tokio::test]
async fn notarize_rejects_non_websocket_request() {
    let app = router(test_state());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/notarize?context_format=Json")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_route_returns_404() {
    let app = router(test_state());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/nonexistent")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
