//! OpenID Foundation RP conformance harness for `rs-identity-model`.
//!
//! Serves the harness protocol `conformance/run_tests.py --harness rust`
//! drives; see `conformance/adding-conformance-profiles.md`.

mod app;
mod classify;
mod rplog;
mod tls;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Reads an environment variable, falling back to `default` when unset.
fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let host = env_or("RP_HOST", "0.0.0.0");
    let port = env_or("RP_PORT", "8891");
    let rp_base_url = env_or("RP_BASE_URL", "http://localhost:8891")
        .trim_end_matches('/')
        .to_owned();
    let log_dir = PathBuf::from(env_or("RP_LOG_DIR", "results/hosted/rp-logs/rust"));
    let cert_path = env_or("SUITE_CERT_FILE", tls::SUITE_CERT_PATH);

    let (http, root) = tls::build_http_client(Path::new(&cert_path))?;
    eprintln!("suite root certificate {cert_path}: {root:?}");

    let state = app::AppState::new(app::Config {
        rp_base_url,
        log_dir,
        allow_http: false,
        http,
    });
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|e| format!("invalid RP_HOST/RP_PORT {host}:{port}: {e}"))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("bind {addr}: {e}"))?;
    eprintln!("conformance-rp-rust listening on {addr}");
    axum::serve(listener, app::router(state))
        .with_graceful_shutdown(shutdown())
        .await
        .map_err(|e| format!("serve: {e}"))
}

/// Resolves on SIGINT or SIGTERM (`docker compose down`), so the container
/// stops promptly as PID 1.
async fn shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}
