mod config;
use crate::config::Settings;
mod http;
use http::download_url_to_bytes;
mod compress;
use compress::extract_first_file_as_bytes;
mod yara;
mod dto;
use dto::UrlDto;
use tracing::info;

use tracing_subscriber;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_appender::rolling;

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
    tracing_subscriber::fmt().with_writer(non_blocking.with_max_level(tracing::Level::INFO)).init();
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

async fn check_content(body: Body) -> impl IntoResponse {
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

    Json(yara::match_yara_rules(&bytes)).into_response()
}

async fn check_url(body: Body) -> impl IntoResponse {
    // 尝试读取整个 body
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

    // 尝试将 body 解析为 JSON，提取 URL
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
    let zip_bytes = match download_url_to_bytes(&req.url).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": "Failed to download file" })),
            )
                .into_response();
        }
    };

    let content = match extract_first_file_as_bytes(&zip_bytes).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": "Failed to unzip file" })),
            )
                .into_response();
        }
    };

    Json(yara::match_yara_rules(&content)).into_response()
}

async fn reload() -> impl IntoResponse {
    yara::reload_rules().unwrap();
    Json(json!({ "result": "ok" })).into_response()
}