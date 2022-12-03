// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate core;

use std::net::IpAddr;
use std::str::FromStr;
use std::{net::SocketAddr, sync::Arc};

use axum::extract::Extension;
use axum::middleware;
use axum::routing::get;
use axum::{routing::post, Router};
use axum_server::tls_rustls::RustlsConfig;
use axum_server::AddrIncomingConfig;
use const_format::concatcp;
use http::{StatusCode, Uri};
use settings::ServerConfig;
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::RollingFileAppender;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{layer::SubscriberExt, Layer};

use xks_proxy::{
    handlers::{decrypt, encrypt, get_health_status, get_key_meta_data},
    sigv4::sigv4_auth,
};

use crate::settings::{parse_rotation, CIPHERTEXT_METADATA, SETTINGS};
use crate::xks_proxy::sigv4::XKSS;
use crate::xks_proxy::ErrorName::InvalidUriPathException;

mod settings;
mod tls;
mod xks_proxy;

const METADATA: &str = "metadata";
const ENCRYPT: &str = "encrypt";
const DECRYPT: &str = "decrypt";
const HEALTH: &str = "health";
const KMS_XKS_V1_PATH: &str = "/kms/xks/v1/";
const URI_PATH_META_DATA: &str = concatcp!(KMS_XKS_V1_PATH, "keys/:key_id/", METADATA);
const URI_PATH_ENCRYPT: &str = concatcp!(KMS_XKS_V1_PATH, "keys/:key_id/", ENCRYPT);
const URI_PATH_DECRYPT: &str = concatcp!(KMS_XKS_V1_PATH, "keys/:key_id/", DECRYPT);
const URI_PATH_HEALTH: &str = concatcp!(KMS_XKS_V1_PATH, HEALTH);
// Used for ALB ping
const URI_PATH_PING: &str = "/ping";
const CARGO_PKG_NAME: &str = env!("CARGO_PKG_NAME");

const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_HASH: &str = if let Some(hash) = option_env!("GIT_HASH") {
    hash
} else {
    "unknown"
};
const VERSION: &str = concatcp!(CARGO_PKG_VERSION, "-", GIT_HASH);

const PING_RESPONSE: &str = concatcp!("pong from ", CARGO_PKG_NAME, " v", VERSION, "\n");

#[tokio::main]
async fn main() {
    let _guard = tracing_init();
    let server_config = &SETTINGS.server;
    tracing::info!(
        service = server_config.service,
        region = server_config.region,
        "Starting",
    );

    let port_http_ping = server_config.port_http_ping();

    if server_config.port == port_http_ping {
        proxy_server(server_config).await;
    } else {
        let proxy = tokio::spawn(proxy_server(server_config));
        let http_health_check = tokio::spawn(http_health_check_server(server_config));
        let _ = tokio::join!(proxy, http_health_check);
    }
}

async fn proxy_server(server_config: &ServerConfig) {
    // https://docs.rs/axum-extra/0.1.2/axum_extra/middleware/middleware_fn/fn.from_fn.html
    let mut router = Router::new();
    for uri_path_prefix in XKSS.keys() {
        tracing::trace!(uri_path_prefix, "Adding url paths");
        router = router
            .route(
                &format!("{uri_path_prefix}{URI_PATH_HEALTH}"),
                post(get_health_status::enact),
            )
            .route(
                &format!("{uri_path_prefix}{URI_PATH_META_DATA}"),
                post(get_key_meta_data::enact),
            )
            .route(
                &format!("{uri_path_prefix}{URI_PATH_ENCRYPT}"),
                post(encrypt::enact),
            )
            .route(
                &format!("{uri_path_prefix}{URI_PATH_DECRYPT}"),
                post(decrypt::enact),
            );
    }
    tracing::trace!("Number of external key stores: {}", XKSS.len());
    router = router
        .route(URI_PATH_PING, get(|| async { PING_RESPONSE }))
        .fallback(fallback);
    let security_config = &SETTINGS.security;

    tracing::info!(is_sigv4_enabled = security_config.is_sigv4_auth_enabled,
        is_tls_enabled = security_config.is_tls_enabled,
        is_mtls_enabled = security_config.is_mtls_enabled,
        secondary_auth = ?security_config.secondary_auth);

    if security_config.is_sigv4_auth_enabled {
        router = router.route_layer(middleware::from_fn(sigv4_auth));
    } else {
        router = router.route_layer(Extension("".to_string()));
    }

    router = router.layer(TraceLayer::new_for_http());

    if server_config.ciphertext_metadata_b64.is_some() {
        // CIPHERTEXT_METADATA.len() eagerly triggers validation of the configuration
        tracing::info!(
            "Ciphertext Metadata has length of {} bytes.",
            CIPHERTEXT_METADATA.len()
        );
    } else {
        tracing::info!("Ciphertext Metadata is not configured.");
    }

    let ip_addr: IpAddr = server_config
        .ip
        .parse()
        .unwrap_or_else(|_| panic!("unable to parse server ip address {}", server_config.ip));
    let socket_addr = SocketAddr::from((ip_addr, server_config.port));

    let ka = &server_config.tcp_keepalive;

    tracing::info!(
        secs = ?ka.tcp_keepalive_secs,
        interval_secs = ?ka.tcp_keepalive_interval_secs,
        retries = ?ka.tcp_keepalive_retries,
        "TCP Keepalive");
    tracing::info!("v{VERSION} listening on {socket_addr} for traffic");

    if security_config.is_tls_enabled {
        let rustls_server_config: rustls::ServerConfig = tls::make_tls_server_config(
            SETTINGS.tls.as_ref().expect("missing tls configuration"),
            security_config.is_mtls_enabled,
        )
        .await
        .expect("server tls misconfiguration");

        let rustls_config: RustlsConfig = RustlsConfig::from_config(Arc::new(rustls_server_config));
        axum_server::bind_rustls(socket_addr, rustls_config)
            .addr_incoming_config(
                AddrIncomingConfig::default()
                    .tcp_keepalive(ka.tcp_keepalive_secs)
                    .tcp_keepalive_interval(ka.tcp_keepalive_interval_secs)
                    .tcp_keepalive_retries(ka.tcp_keepalive_retries)
                    .build(),
            )
            .serve(router.into_make_service())
            .await
            .expect("https server address binding failed");
    } else {
        axum_server::bind(socket_addr)
            .addr_incoming_config(
                AddrIncomingConfig::default()
                    .tcp_keepalive(ka.tcp_keepalive_secs)
                    .tcp_keepalive_interval(ka.tcp_keepalive_interval_secs)
                    .tcp_keepalive_retries(ka.tcp_keepalive_retries)
                    .build(),
            )
            .serve(router.into_make_service())
            .await
            .expect("http server address binding failed");
    }
}

async fn http_health_check_server(server_config: &ServerConfig) {
    let health_check_router = Router::new()
        .route(URI_PATH_PING, get(|| async { PING_RESPONSE }))
        .fallback(fallback);
    let ip_addr: IpAddr = server_config
        .ip
        .parse()
        .unwrap_or_else(|_| panic!("unable to parse server ip address {}", server_config.ip));
    let socket_addr = SocketAddr::from((ip_addr, server_config.port_http_ping()));
    tracing::info!("http://{socket_addr}/ping available for health check");
    let ka_config = &server_config.tcp_keepalive;
    axum_server::bind(socket_addr)
        .addr_incoming_config(
            AddrIncomingConfig::default()
                .tcp_keepalive(ka_config.tcp_keepalive_secs)
                .tcp_keepalive_interval(ka_config.tcp_keepalive_interval_secs)
                .tcp_keepalive_retries(ka_config.tcp_keepalive_retries)
                .build(),
        )
        .serve(health_check_router.into_make_service())
        .await
        .expect("http health check address binding failed");
}

/// Initialize tracing to output to either the stdout or file according to the tracing configurations.
/// Note it's necessary to return the tracing's [WorkerGuard] to [main] for the file logging, if enabled, to work.
/// See [struct.WorkerGuard.html](https://docs.rs/tracing-appender/latest/tracing_appender/non_blocking/struct.WorkerGuard.html)
/// for more details.
fn tracing_init() -> Option<WorkerGuard> {
    let tracing_config = &SETTINGS.tracing;
    let is_stdout_writer_enabled = tracing_config.is_stdout_writer_enabled;
    let is_file_writer_enabled = tracing_config.is_file_writer_enabled;

    if !is_stdout_writer_enabled && !is_file_writer_enabled {
        eprintln!(
            "Tracing to both stdout and file are disabled.  Are you sure this is intentional?"
        );
        return None;
    }

    let level_string = tracing_config
        .level
        .as_ref()
        .expect("Missing tracing level configuration");
    let level = Level::from_str(level_string)
        .unwrap_or_else(|_| panic!("unrecognized trace level {}", level_string));

    // Source: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/layer/index.html#runtime-configuration-with-layers
    let mut layers = Vec::new();
    if is_stdout_writer_enabled {
        let layer = tracing_subscriber::fmt::layer()
            .with_thread_names(true)
            .with_line_number(true)
            .with_filter(LevelFilter::from_level(level))
            .boxed();
        layers.push(layer);
    }

    let guard = if is_file_writer_enabled {
        let directory = tracing_config
            .directory
            .as_ref()
            .expect("Missing log directory configuration");
        let file_name_prefix = tracing_config
            .file_prefix
            .as_ref()
            .expect("Missing log file prefix configuration");
        let rotation_kind = tracing_config
            .rotation_kind
            .as_ref()
            .expect("Missing log file rotation kind");
        let rotation = parse_rotation(rotation_kind);
        let rolling_file_appender = RollingFileAppender::new(rotation, directory, file_name_prefix);
        let (non_blocking, guard) = tracing_appender::non_blocking(rolling_file_appender);

        let layer = tracing_subscriber::fmt::layer()
            .with_thread_names(true)
            .with_line_number(true)
            .with_target(true)
            .with_writer(non_blocking)
            .with_filter(LevelFilter::from_level(level))
            .boxed();

        layers.push(layer);
        Some(guard)
    } else {
        None
    };

    tracing_subscriber::registry().with(layers).init();
    tracing::info!(level = level_string, is_file_writer_enabled, "Tracing");
    if is_file_writer_enabled {
        tracing::info!(
            rotation_kind = tracing_config.rotation_kind.as_ref().unwrap(),
            "Tracing file"
        );
    }
    guard
}

async fn fallback(uri: Uri) -> (StatusCode, axum::Json<xks_proxy::Error>) {
    InvalidUriPathException.as_axum_error(format!("No route for {uri}"))
}
