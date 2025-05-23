mod config;
use crate::config::Settings;
mod http;
mod compress;
mod dto;
mod yara;
use axum::extract::Query;
use dto::UrlDto;
use std::collections::HashMap;
use tracing::info;

use tracing_appender::rolling;
use tracing_subscriber;
use tracing_subscriber::fmt::writer::MakeWriterExt;

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};

use serde_json::json;

#[tokio::main]
async fn main() {
    let file_appender = rolling::daily("logs", "app.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_writer(non_blocking.with_max_level(tracing::Level::INFO))
        .init();
    info!("starting...");
    let settings: Settings = Settings::from_yaml("config/config.yaml").unwrap();
    info!("Listening on: {}", settings.server.address);
    info!("Registered routes:");
    info!("  POST {}", settings.server.url_path.content);
    info!("  POST {}", settings.server.url_path.url);
    info!("  POST {}", settings.server.url_path.reload);
    yara::init_rules(settings.yara.rule_dir.into()).unwrap();

    let app = Router::new()
        .route(&settings.server.url_path.content, post(check_content))
        .route(&settings.server.url_path.url, post(check_url))
        .route(&settings.server.url_path.reload, post(reload));

    let listener = tokio::net::TcpListener::bind(settings.server.address)
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn check_content(
    Query(params): Query<HashMap<String, String>>,
    body: Body,
) -> impl IntoResponse {
    let bytes = match to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Failed to read body" })),
            )
                .into_response();
        }
    };
    let need_to_unzip = params
        .get("need_to_unzip")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    Json( yara::match_yara_rules_with_unzip(&bytes, need_to_unzip)).into_response()
}

async fn check_url(body: Body) -> impl IntoResponse {
    let bytes = match to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Failed to read body" })),
            )
                .into_response();
        }
    };

    let req: UrlDto = match serde_json::from_slice(&bytes) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Invalid JSON" })),
            )
                .into_response();
        }
    };
    let yara_result = yara::match_yara_rules_with_unzip_and_url(&req.url, req.need_to_unzip).await;
    Json(yara_result).into_response()    
}

async fn reload() -> impl IntoResponse {
    yara::reload_rules().unwrap();
    Json(json!({ "result": "ok" })).into_response()
}
