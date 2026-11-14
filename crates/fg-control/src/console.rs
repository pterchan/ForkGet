//! Optional, read-only delivery of the packaged local console.

use std::{env, path::PathBuf, sync::Arc};

use axum::{
    Router,
    body::Body,
    extract::Path,
    http::{HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{any, get},
};

use crate::ControlError;

const ASSET_LIMIT: u64 = 8 * 1024 * 1024;

pub(crate) fn routes<S>() -> Result<Router<S>, ControlError>
where
    S: Clone + Send + Sync + 'static,
{
    directory_routes(env::var_os("FG_CONSOLE_DIR").map(PathBuf::from))
}

fn directory_routes<S>(directory: Option<PathBuf>) -> Result<Router<S>, ControlError>
where
    S: Clone + Send + Sync + 'static,
{
    let Some(directory) = directory else {
        return Ok(Router::new());
    };
    let root = directory
        .canonicalize()
        .map_err(|_| ControlError::Config("FG_CONSOLE_DIR"))?;
    if !root.is_dir() || !root.join("index.html").is_file() {
        return Err(ControlError::Config("FG_CONSOLE_DIR"));
    }
    let root = Arc::new(root);
    let index_root = root.clone();
    Ok(Router::new()
        .route(
            "/",
            get(move || asset(index_root.clone(), "index.html".into())),
        )
        .route(
            "/{*asset}",
            any(move |method: Method, Path(name): Path<String>| {
                let root = root.clone();
                async move {
                    if method != Method::GET && method != Method::HEAD {
                        return StatusCode::NOT_FOUND.into_response();
                    }
                    let mut response = asset(root, name).await;
                    if method == Method::HEAD {
                        *response.body_mut() = Body::empty();
                    }
                    response
                }
            }),
        ))
}

async fn asset(root: Arc<PathBuf>, name: String) -> Response {
    let Some(content_type) = content_type(&name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(path) = tokio::fs::canonicalize(root.join(&name)).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !path.starts_with(root.as_ref()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(metadata) = tokio::fs::metadata(&path).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !metadata.is_file() || metadata.len() > ASSET_LIMIT {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(bytes) = tokio::fs::read(path).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut response = Response::new(Body::from(bytes));
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response
}

fn content_type(name: &str) -> Option<&'static str> {
    if name.len() > 1024
        || name.contains('\\')
        || name
            .split('/')
            .any(|part| part.is_empty() || part.starts_with('.'))
        || name.starts_with("api/")
        || name.starts_with("internal/")
        || name.starts_with("v1/")
    {
        return None;
    }
    match name.rsplit('.').next()? {
        "html" if name == "index.html" => Some("text/html; charset=utf-8"),
        "js" => Some("text/javascript; charset=utf-8"),
        "json" if name == "_app/version.json" => Some("application/json"),
        "css" => Some("text/css; charset=utf-8"),
        "svg" => Some("image/svg+xml"),
        "png" => Some("image/png"),
        "webp" => Some("image/webp"),
        "ico" => Some("image/x-icon"),
        "woff" => Some("font/woff"),
        "woff2" => Some("font/woff2"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn serves_only_packaged_assets_and_keeps_api_failures_as_http_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        std::fs::write(root.path().join("index.html"), "<h1>Forkget</h1>")?;
        std::fs::write(root.path().join("app.js"), "export const version=1;")?;
        std::fs::write(root.path().join(".env"), "private")?;
        std::fs::write(root.path().join("app.js.map"), "private paths")?;
        let router: Router = directory_routes(Some(root.path().into()))?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let client = fg_protocol_common::loopback_client(std::time::Duration::from_secs(2))?;
        let index = client.get(&origin).send().await?;
        assert_eq!(index.status(), StatusCode::OK);
        assert_eq!(index.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(index.headers()["x-content-type-options"], "nosniff");
        assert_eq!(index.text().await?, "<h1>Forkget</h1>");
        let script = client.get(format!("{origin}/app.js")).send().await?;
        assert_eq!(script.status(), StatusCode::OK);
        for path in [
            "/.env",
            "/app.js.map",
            "/internal/app.js",
            "/api/v1/missing",
            "/missing.js",
        ] {
            assert_eq!(
                client.get(format!("{origin}{path}")).send().await?.status(),
                StatusCode::NOT_FOUND
            );
        }
        assert_eq!(
            client
                .post(format!("{origin}/api/internal/v1/resolve"))
                .send()
                .await?
                .status(),
            StatusCode::NOT_FOUND
        );
        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn refuses_symlink_escape_and_invalid_asset_roots()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        assert!(directory_routes::<()>(Some(root.path().into())).is_err());
        std::fs::write(root.path().join("index.html"), "console")?;
        std::fs::write(outside.path().join("outside.js"), "private")?;
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                outside.path().join("outside.js"),
                root.path().join("escape.js"),
            )?;
            assert_eq!(
                asset(Arc::new(root.path().canonicalize()?), "escape.js".into())
                    .await
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
        assert!(content_type("../outside.js").is_none());
        assert!(content_type("api/internal.js").is_none());
        Ok(())
    }
}
