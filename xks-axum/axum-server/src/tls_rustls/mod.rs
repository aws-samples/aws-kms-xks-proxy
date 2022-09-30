//! Tls implementation using [`rustls`].
//!
//! # Example
//!
//! ```rust,no_run
//! use axum::{routing::get, Router};
//! use axum_server::tls_rustls::RustlsConfig;
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() {
//!     let app = Router::new().route("/", get(|| async { "Hello, world!" }));
//!
//!     let config = RustlsConfig::from_pem_file(
//!         "examples/self-signed-certs/cert.pem",
//!         "examples/self-signed-certs/key.pem",
//!     )
//!     .await
//!     .unwrap();
//!
//!     let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
//!     println!("listening on {}", addr);
//!     axum_server::bind_rustls(addr, config)
//!         .serve(app.into_make_service())
//!         .await
//!         .unwrap();
//! }
//! ```

use self::future::RustlsAcceptorFuture;
use crate::{
    accept::{Accept, DefaultAcceptor},
    server::{io_other, Server},
};
use arc_swap::ArcSwap;
use rustls::{Certificate, PrivateKey, ServerConfig};
use std::time::Duration;
use std::{fmt, io, net::SocketAddr, path::Path, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::spawn_blocking,
};
use tokio_rustls::server::TlsStream;

pub(crate) mod export {
    use super::*;

    /// Create a tls server that will bind to provided address.
    #[cfg_attr(docsrs, doc(cfg(feature = "tls-rustls")))]
    pub fn bind_rustls(addr: SocketAddr, config: RustlsConfig) -> Server<RustlsAcceptor> {
        super::bind_rustls(addr, config)
    }

    /// Create a tls server from existing `std::net::TcpListener`.
    #[cfg_attr(docsrs, doc(cfg(feature = "tls-rustls")))]
    pub fn from_tcp_rustls(
        listener: std::net::TcpListener,
        config: RustlsConfig,
    ) -> Server<RustlsAcceptor> {
        let acceptor = RustlsAcceptor::new(config);

        Server::from_tcp(listener).acceptor(acceptor)
    }
}

pub mod future;

/// Create a tls server that will bind to provided address.
pub fn bind_rustls(addr: SocketAddr, config: RustlsConfig) -> Server<RustlsAcceptor> {
    let acceptor = RustlsAcceptor::new(config);

    Server::bind(addr).acceptor(acceptor)
}

/// Create a tls server from existing `std::net::TcpListener`.
pub fn from_tcp_rustls(
    listener: std::net::TcpListener,
    config: RustlsConfig,
) -> Server<RustlsAcceptor> {
    let acceptor = RustlsAcceptor::new(config);

    Server::from_tcp(listener).acceptor(acceptor)
}

/// Tls acceptor using rustls.
#[derive(Clone)]
pub struct RustlsAcceptor<A = DefaultAcceptor> {
    inner: A,
    config: RustlsConfig,
    handshake_timeout: Duration,
}

impl RustlsAcceptor {
    /// Create a new rustls acceptor.
    pub fn new(config: RustlsConfig) -> Self {
        let inner = DefaultAcceptor::new();

        #[cfg(not(test))]
        let handshake_timeout = Duration::from_secs(10);

        // Don't force tests to wait too long.
        #[cfg(test)]
        let handshake_timeout = Duration::from_secs(1);

        Self {
            inner,
            config,
            handshake_timeout,
        }
    }

    /// Override the default TLS handshake timeout of 10 seconds, except during testing.
    pub fn handshake_timeout(mut self, val: Duration) -> Self {
        self.handshake_timeout = val;
        self
    }
}

impl<A> RustlsAcceptor<A> {
    /// Overwrite inner acceptor.
    pub fn acceptor<Acceptor>(self, acceptor: Acceptor) -> RustlsAcceptor<Acceptor> {
        RustlsAcceptor {
            inner: acceptor,
            config: self.config,
            handshake_timeout: self.handshake_timeout,
        }
    }
}

impl<A, I, S> Accept<I, S> for RustlsAcceptor<A>
where
    A: Accept<I, S>,
    A::Stream: AsyncRead + AsyncWrite + Unpin,
{
    type Stream = TlsStream<A::Stream>;
    type Service = A::Service;
    type Future = RustlsAcceptorFuture<A::Future, A::Stream, A::Service>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner_future = self.inner.accept(stream, service);
        let config = self.config.clone();

        RustlsAcceptorFuture::new(inner_future, config, self.handshake_timeout)
    }
}

impl<A> fmt::Debug for RustlsAcceptor<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RustlsAcceptor").finish()
    }
}

/// Rustls configuration.
#[derive(Clone)]
pub struct RustlsConfig {
    inner: Arc<ArcSwap<ServerConfig>>,
}

impl RustlsConfig {
    /// Create config from `Arc<`[`ServerConfig`]`>`.
    pub fn from_config(config: Arc<ServerConfig>) -> Self {
        let inner = Arc::new(ArcSwap::new(config));

        Self { inner }
    }

    /// Create config from DER-encoded data.
    ///
    /// The certificate must be DER-encoded X.509.
    ///
    /// The private key must be DER-encoded ASN.1 in either PKCS#8 or PKCS#1 format.
    pub async fn from_der(cert: Vec<Vec<u8>>, key: Vec<u8>) -> io::Result<Self> {
        let server_config = spawn_blocking(|| config_from_der(cert, key))
            .await
            .unwrap()?;
        let inner = Arc::new(ArcSwap::from_pointee(server_config));

        Ok(Self { inner })
    }

    /// Create config from PEM formatted data.
    ///
    /// Certificate and private key must be in PEM format.
    pub async fn from_pem(cert: Vec<u8>, key: Vec<u8>) -> io::Result<Self> {
        let server_config = spawn_blocking(|| config_from_pem(cert, key))
            .await
            .unwrap()?;
        let inner = Arc::new(ArcSwap::from_pointee(server_config));

        Ok(Self { inner })
    }

    /// Create config from PEM formatted files.
    ///
    /// Contents of certificate file and private key file must be in PEM format.
    pub async fn from_pem_file(cert: impl AsRef<Path>, key: impl AsRef<Path>) -> io::Result<Self> {
        let server_config = config_from_pem_file(cert, key).await?;
        let inner = Arc::new(ArcSwap::from_pointee(server_config));

        Ok(Self { inner })
    }

    /// Get  inner `Arc<`[`ServerConfig`]`>`.
    pub fn get_inner(&self) -> Arc<ServerConfig> {
        self.inner.load_full()
    }

    /// Reload config from `Arc<`[`ServerConfig`]`>`.
    pub fn reload_from_config(&self, config: Arc<ServerConfig>) {
        self.inner.store(config);
    }

    /// Reload config from DER-encoded data.
    ///
    /// The certificate must be DER-encoded X.509.
    ///
    /// The private key must be DER-encoded ASN.1 in either PKCS#8 or PKCS#1 format.
    pub async fn reload_from_der(&self, cert: Vec<Vec<u8>>, key: Vec<u8>) -> io::Result<()> {
        let server_config = spawn_blocking(|| config_from_der(cert, key))
            .await
            .unwrap()?;
        let inner = Arc::new(server_config);

        self.inner.store(inner);

        Ok(())
    }

    /// Reload config from PEM formatted data.
    ///
    /// Certificate and private key must be in PEM format.
    pub async fn reload_from_pem(&self, cert: Vec<u8>, key: Vec<u8>) -> io::Result<()> {
        let server_config = spawn_blocking(|| config_from_pem(cert, key))
            .await
            .unwrap()?;
        let inner = Arc::new(server_config);

        self.inner.store(inner);

        Ok(())
    }

    /// Reload config from PEM formatted files.
    ///
    /// Contents of certificate file and private key file must be in PEM format.
    pub async fn reload_from_pem_file(
        &self,
        cert: impl AsRef<Path>,
        key: impl AsRef<Path>,
    ) -> io::Result<()> {
        let server_config = config_from_pem_file(cert, key).await?;
        let inner = Arc::new(server_config);

        self.inner.store(inner);

        Ok(())
    }
}

impl fmt::Debug for RustlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RustlsConfig").finish()
    }
}

fn config_from_der(cert: Vec<Vec<u8>>, key: Vec<u8>) -> io::Result<ServerConfig> {
    let cert = cert.into_iter().map(Certificate).collect();
    let key = PrivateKey(key);

    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .map_err(io_other)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(config)
}

fn config_from_pem(cert: Vec<u8>, key: Vec<u8>) -> io::Result<ServerConfig> {
    use rustls_pemfile::Item;

    let cert = rustls_pemfile::certs(&mut cert.as_ref())?;
    let key = match rustls_pemfile::read_one(&mut key.as_ref())? {
        Some(Item::RSAKey(key)) | Some(Item::PKCS8Key(key)) | Some(Item::ECKey(key)) => key,
        _ => return Err(io_other("private key format not supported")),
    };

    config_from_der(cert, key)
}

async fn config_from_pem_file(
    cert: impl AsRef<Path>,
    key: impl AsRef<Path>,
) -> io::Result<ServerConfig> {
    let cert = tokio::fs::read(cert.as_ref()).await?;
    let key = tokio::fs::read(key.as_ref()).await?;

    config_from_pem(cert, key)
}

#[cfg(test)]
mod tests {
    use crate::{
        handle::Handle,
        tls_rustls::{self, RustlsConfig},
    };
    use axum::{routing::get, Router};
    use bytes::Bytes;
    use http::{response, Request};
    use hyper::{
        client::conn::{handshake, SendRequest},
        Body,
    };
    use rustls::{
        client::{ServerCertVerified, ServerCertVerifier},
        Certificate, ClientConfig, ServerName,
    };
    use std::{
        convert::TryFrom,
        io,
        net::SocketAddr,
        sync::Arc,
        time::{Duration, SystemTime},
    };
    use tokio::time::sleep;
    use tokio::{net::TcpStream, task::JoinHandle, time::timeout};
    use tokio_rustls::TlsConnector;
    use tower::{Service, ServiceExt};

    #[tokio::test]
    async fn start_and_request() {
        let (_handle, _server_task, addr) = start_server().await;

        let (mut client, _conn) = connect(addr).await;

        let (_parts, body) = send_empty_request(&mut client).await;

        assert_eq!(body.as_ref(), b"Hello, world!");
    }

    #[ignore]
    #[tokio::test]
    async fn tls_timeout() {
        let (handle, _server_task, addr) = start_server().await;
        assert_eq!(handle.connection_count(), 0);

        // We intentionally avoid driving a TLS handshake to completion.
        let _stream = TcpStream::connect(addr).await.unwrap();

        sleep(Duration::from_millis(500)).await;
        assert_eq!(handle.connection_count(), 1);

        tokio::time::sleep(Duration::from_millis(1000)).await;
        // Timeout defaults to 1s during testing, and we have waited 1.5 seconds.
        assert_eq!(handle.connection_count(), 0);
    }

    #[tokio::test]
    async fn test_reload() {
        let handle = Handle::new();

        let config = RustlsConfig::from_pem_file(
            "examples/self-signed-certs/cert.pem",
            "examples/self-signed-certs/key.pem",
        )
        .await
        .unwrap();

        let server_handle = handle.clone();
        let rustls_config = config.clone();
        tokio::spawn(async move {
            let app = Router::new().route("/", get(|| async { "Hello, world!" }));

            let addr = SocketAddr::from(([127, 0, 0, 1], 0));

            tls_rustls::bind_rustls(addr, rustls_config)
                .handle(server_handle)
                .serve(app.into_make_service())
                .await
        });

        let addr = handle.listening().await.unwrap();

        let cert_a = get_first_cert(addr).await;
        let mut cert_b = get_first_cert(addr).await;

        assert_eq!(cert_a, cert_b);

        config
            .reload_from_pem_file(
                "examples/self-signed-certs/reload/cert.pem",
                "examples/self-signed-certs/reload/key.pem",
            )
            .await
            .unwrap();

        cert_b = get_first_cert(addr).await;

        assert_ne!(cert_a, cert_b);

        config
            .reload_from_pem_file(
                "examples/self-signed-certs/cert.pem",
                "examples/self-signed-certs/key.pem",
            )
            .await
            .unwrap();

        cert_b = get_first_cert(addr).await;

        assert_eq!(cert_a, cert_b);
    }

    #[tokio::test]
    async fn test_shutdown() {
        let (handle, _server_task, addr) = start_server().await;

        let (mut client, conn) = connect(addr).await;

        handle.shutdown();

        let response_future_result = client
            .ready()
            .await
            .unwrap()
            .call(Request::new(Body::empty()))
            .await;

        assert!(response_future_result.is_err());

        // Connection task should finish soon.
        let _ = timeout(Duration::from_secs(1), conn).await.unwrap();
    }

    #[tokio::test]
    async fn test_graceful_shutdown() {
        let (handle, server_task, addr) = start_server().await;

        let (mut client, conn) = connect(addr).await;

        handle.graceful_shutdown(None);

        let (_parts, body) = send_empty_request(&mut client).await;

        assert_eq!(body.as_ref(), b"Hello, world!");

        // Disconnect client.
        conn.abort();

        // Server task should finish soon.
        let server_result = timeout(Duration::from_secs(1), server_task)
            .await
            .unwrap()
            .unwrap();

        assert!(server_result.is_ok());
    }

    #[ignore]
    #[tokio::test]
    async fn test_graceful_shutdown_timed() {
        let (handle, server_task, addr) = start_server().await;

        let (mut client, _conn) = connect(addr).await;

        handle.graceful_shutdown(Some(Duration::from_millis(250)));

        let (_parts, body) = send_empty_request(&mut client).await;

        assert_eq!(body.as_ref(), b"Hello, world!");

        // Don't disconnect client.
        // conn.abort();

        // Server task should finish soon.
        let server_result = timeout(Duration::from_secs(1), server_task)
            .await
            .unwrap()
            .unwrap();

        assert!(server_result.is_ok());
    }

    async fn start_server() -> (Handle, JoinHandle<io::Result<()>>, SocketAddr) {
        let handle = Handle::new();

        let server_handle = handle.clone();
        let server_task = tokio::spawn(async move {
            let app = Router::new().route("/", get(|| async { "Hello, world!" }));

            let config = RustlsConfig::from_pem_file(
                "examples/self-signed-certs/cert.pem",
                "examples/self-signed-certs/key.pem",
            )
            .await?;

            let addr = SocketAddr::from(([127, 0, 0, 1], 0));

            tls_rustls::bind_rustls(addr, config)
                .handle(server_handle)
                .serve(app.into_make_service())
                .await
        });

        let addr = handle.listening().await.unwrap();

        (handle, server_task, addr)
    }

    async fn get_first_cert(addr: SocketAddr) -> Certificate {
        let stream = TcpStream::connect(addr).await.unwrap();
        let tls_stream = tls_connector().connect(dns_name(), stream).await.unwrap();

        let (_io, client_connection) = tls_stream.into_inner();

        client_connection.peer_certificates().unwrap()[0].clone()
    }

    async fn connect(addr: SocketAddr) -> (SendRequest<Body>, JoinHandle<()>) {
        let stream = TcpStream::connect(addr).await.unwrap();
        let tls_stream = tls_connector().connect(dns_name(), stream).await.unwrap();

        let (send_request, connection) = handshake(tls_stream).await.unwrap();

        let task = tokio::spawn(async move {
            let _ = connection.await;
        });

        (send_request, task)
    }

    async fn send_empty_request(client: &mut SendRequest<Body>) -> (response::Parts, Bytes) {
        let (parts, body) = client
            .ready()
            .await
            .unwrap()
            .call(Request::new(Body::empty()))
            .await
            .unwrap()
            .into_parts();
        let body = hyper::body::to_bytes(body).await.unwrap();

        (parts, body)
    }

    fn tls_connector() -> TlsConnector {
        struct NoVerify;

        impl ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _end_entity: &Certificate,
                _intermediates: &[Certificate],
                _server_name: &ServerName,
                _scts: &mut dyn Iterator<Item = &[u8]>,
                _ocsp_response: &[u8],
                _now: SystemTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
        }

        let mut client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();

        client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        TlsConnector::from(Arc::new(client_config))
    }

    fn dns_name() -> ServerName {
        ServerName::try_from("localhost").unwrap()
    }
}
