// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use std::sync::Arc;
use std::time::SystemTime;
use std::{
    fs::File,
    io::{BufReader, ErrorKind},
};

use rustls::server::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    server::AllowAnyAuthenticatedClient, Certificate, DistinguishedNames, PrivateKey,
    RootCertStore, ServerConfig,
};
use rustls_pemfile::Item;
use tokio::io;
use webpki::DnsNameRef;

use crate::settings::TLSConfig;

// Originally copied from
// https://github.com/programatik29/axum-server/blob/344a9569e8195673c41e05bc5f46de35b3e273fe/src/tls_rustls/mod.rs#L225-L260

type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) fn io_other<E: Into<BoxError>>(error: E) -> io::Error {
    io::Error::new(ErrorKind::Other, error)
}

// https://github.com/hyperium/tonic/blob/master/examples/src/tls_client_auth/server.rs
// https://discord.com/channels/500028886025895936/942633431626547280/942635956400431115
pub async fn make_tls_server_config(
    config: &TLSConfig,
    is_mtls_enabled: bool,
) -> io::Result<ServerConfig> {
    let builder = ServerConfig::builder().with_safe_defaults();

    let cert = tokio::fs::read(config.tls_cert_pem.as_str()).await?;
    let certs = rustls_pemfile::certs(&mut cert.as_ref())?;
    let cert_chain = certs.into_iter().map(Certificate).collect();

    let key = tokio::fs::read(config.tls_key_pem.as_str()).await?;
    let key_der = match rustls_pemfile::read_one(&mut key.as_ref())? {
        Some(Item::RSAKey(key)) | Some(Item::PKCS8Key(key)) => key,
        _ => return Err(io_other("private key not found")),
    };
    let private_key = PrivateKey(key_der);

    let server_identity_builder = if is_mtls_enabled {
        let root_cert_store = make_client_root_cert_store(
            config
                .mtls_client_ca_pem
                .as_ref()
                .expect("missing client CA pem file")
                .as_str(),
        );
        builder.with_client_cert_verifier(Arc::new(AllowAuthenticatedClient::new(
            root_cert_store,
            config
                .mtls_client_dns_name
                .as_ref()
                .expect("missing mTLS client dns name configuration"),
        )))
    } else {
        builder.with_no_client_auth()
    };
    server_identity_builder
        .with_single_cert(cert_chain, private_key)
        .map_err(io_other)
}

// See example at https://github.com/rustls/rustls/blob/main/rustls-mio/examples/tlsserver.rs
fn make_client_root_cert_store(mtls_client_ca_pem: &str) -> RootCertStore {
    let root_certs = load_certs(mtls_client_ca_pem);
    let mut client_root_cert_store = RootCertStore::empty();
    for root_cert in root_certs {
        client_root_cert_store
            .add(&root_cert)
            .unwrap_or_else(|_| panic!("failed to add client root CA {:?}", root_cert));
    }
    client_root_cert_store
}

fn load_certs(filename: &str) -> Vec<Certificate> {
    let cert_file = File::open(filename)
        .unwrap_or_else(|_| panic!("failed to open certificate file '{}'", filename));
    let mut reader = BufReader::new(cert_file);
    rustls_pemfile::certs(&mut reader)
        .unwrap_or_else(|_| panic!("failed to extract certificates from file '{}'", filename))
        .iter()
        .map(|bytes| Certificate(bytes.clone()))
        .collect()
}

// Copied from https://github.com/rustls/rustls/blob/v/0.20.6/rustls/src/verify.rs#L579-L589
fn pki_error(error: webpki::Error) -> rustls::Error {
    use webpki::Error::*;
    match error {
        BadDer | BadDerTime => rustls::Error::InvalidCertificateEncoding,
        InvalidSignatureForPublicKey => rustls::Error::InvalidCertificateSignature,
        UnsupportedSignatureAlgorithm | UnsupportedSignatureAlgorithmForPublicKey => {
            rustls::Error::InvalidCertificateSignatureType
        }
        e => rustls::Error::InvalidCertificateData(format!("invalid peer certificate: {e}")),
    }
}

// Borrowed from https://github.com/rustls/rustls/blob/v/0.20.6/rustls/src/verify.rs#L497-L532
pub struct AllowAuthenticatedClient {
    delegate: Arc<dyn ClientCertVerifier>,
    client_dns_name: String,
}

impl AllowAuthenticatedClient {
    /// Construct a new `AllowAuthenticatedClient`.
    ///
    /// `roots` is the list of trust anchors to use for certificate validation.
    pub fn new(roots: RootCertStore, client_dns_name: &str) -> AllowAuthenticatedClient {
        Self {
            delegate: AllowAnyAuthenticatedClient::new(roots),
            client_dns_name: client_dns_name.to_string(),
        }
    }
}

impl ClientCertVerifier for AllowAuthenticatedClient {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_root_subjects(&self) -> Option<DistinguishedNames> {
        self.delegate.client_auth_root_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        now: SystemTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // https://github.com/briansmith/webpki/issues/257
        let cert = webpki::EndEntityCert::try_from(end_entity.0.as_ref()).map_err(pki_error)?;
        let dns_name = DnsNameRef::try_from_ascii_str(self.client_dns_name.as_str()).unwrap();
        cert.verify_is_valid_for_dns_name(dns_name)
            .map_err(pki_error)?;
        self.delegate
            .verify_client_cert(end_entity, intermediates, now)
    }
}
