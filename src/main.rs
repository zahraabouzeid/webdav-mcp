use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use webdav_mcp::app;
use webdav_mcp::config::{Settings, user_agent};
use webdav_mcp::network::Addresses;

#[tokio::main]
async fn main() -> ExitCode {
    let settings = match Settings::from_env() {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let result = match std::env::args().nth(1).as_deref() {
        None => serve(&settings).await,
        Some("health") => check_health(&settings).await,
        Some(other) => Err(format!(
            "unknown command {other:?}, run without arguments to start the server or with \
             \"health\" to check a running one"
        )),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn serve(settings: &Settings) -> Result<(), String> {
    let router = app(settings, Addresses::PublicOnly)?;
    let address = format!("{}:{}", settings.host, settings.port);
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .map_err(|error| format!("could not listen on {address}: {error}"))?;
    println!("webdav-mcp listens on http://{address}/mcp");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await
    .map_err(|error| error.to_string())
}

async fn check_health(settings: &Settings) -> Result<(), String> {
    let url = format!("http://127.0.0.1:{}/health", settings.port);
    let response = reqwest::Client::builder()
        .user_agent(user_agent())
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|error| error.to_string())?
        .get(&url)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("{url} answered with HTTP {}", response.status()))
    }
}

async fn shutdown() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}
