// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::time::Duration;
use std::{env, fs};

use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine;

use lazy_static::lazy_static;
use serde_derive::Deserialize;
use serde_with::{serde_as, DurationSeconds};
use tracing::instrument;
use tracing_appender::rolling::Rotation;

use crate::settings;

pub const XKS_PROXY_SETTINGS_TOML: &str = "XKS_PROXY_SETTINGS_TOML";
pub const PKCS11_HSM_MODULE: &str = "PKCS11_HSM_MODULE";
pub const PKCS11_LOGGER_LIBRARY_PATH: &str = "PKCS11_LOGGER_LIBRARY_PATH";
pub const PKCS11_LOGGER_LOG_FILE_PATH: &str = "PKCS11_LOGGER_LOG_FILE_PATH";
pub const PKCS11_LOGGER_FLAGS: &str = "PKCS11_LOGGER_FLAGS";

// Used only if the "XKS_PROXY_SETTINGS_TOML" environment variable is not explicitly set
const DEFAULT_BOOTSTRAP_TOML: &str = "configuration/bootstrap.toml";

pub const CIPHERTEXT_METATDATA_MAX_BYTE_LENGTH: usize = 20;

lazy_static! {
    pub static ref SETTINGS: Settings = settings::load_settings();
    pub static ref CIPHERTEXT_METADATA: Vec<u8> =
        load_ciphertext_metadata(&SETTINGS.server.ciphertext_metadata_b64);
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub server: ServerConfig,
    pub security: SecurityConfig,
    pub tls: Option<TLSConfig>,
    pub tracing: TracingConfig,
    pub pkcs11: Pkcs11Config,
    pub pkcs11_logger: Option<Pkcs11LoggerConfig>,
    pub limits: LimitsConfig,
    pub hsm_capabilities: HsmCapabilitiesConfig,
    pub external_key_stores: Vec<ExternalKeyStore>,
}

#[serde_as]
#[derive(Deserialize, Debug)]
pub struct ServerConfig {
    pub ip: String,
    pub port: u16,
    // Port used for http ping.  Defaults to 80.
    port_http_ping: Option<u16>,
    pub region: String,
    pub service: String,
    pub ciphertext_metadata_b64: Option<String>,
    pub tcp_keepalive: TcpKeepaliveConfig,
}

impl ServerConfig {
    pub fn port_http_ping(&self) -> u16 {
        self.port_http_ping.unwrap_or(80)
    }
}

#[serde_as]
#[derive(Deserialize, Debug, Clone)]
pub struct TcpKeepaliveConfig {
    // https://stackoverflow.com/questions/70184303/how-to-serialize-and-deserialize-chronoduration
    #[serde_as(as = "Option<DurationSeconds<u64>>")]
    pub tcp_keepalive_secs: Option<Duration>,

    #[serde_as(as = "Option<DurationSeconds<u64>>")]
    pub tcp_keepalive_interval_secs: Option<Duration>,

    pub tcp_keepalive_retries: Option<u32>,
}

#[non_exhaustive]
#[derive(PartialEq, Eq, Debug, Deserialize, Clone)]
pub enum SecondaryAuth {
    Oso,
    // Can add support for other providers such as OPA
}

#[derive(Debug, Deserialize, Clone)]
pub struct OsoConfig {
    pub polar_file_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    pub is_sigv4_auth_enabled: bool,
    pub is_tls_enabled: bool,
    pub is_mtls_enabled: bool,

    pub secondary_auth: Option<SecondaryAuth>,
    pub oso: Option<OsoConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TLSConfig {
    pub tls_cert_pem: String,
    pub tls_key_pem: String,
    pub mtls_client_ca_pem: Option<String>,
    pub mtls_client_dns_name: Option<String>,
}

pub fn parse_rotation(rotation_kind: &str) -> Rotation {
    match rotation_kind.to_uppercase().as_str() {
        "MINUTELY" => Rotation::MINUTELY,
        "HOURLY" => Rotation::HOURLY,
        "DAILY" => Rotation::DAILY,
        "NEVER" => Rotation::NEVER,
        _ => panic!("Unrecognized rotation kind '{}'", rotation_kind),
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct TracingConfig {
    pub is_stdout_writer_enabled: bool,
    pub is_file_writer_enabled: bool,
    pub level: Option<String>,
    pub directory: Option<String>,
    pub file_prefix: Option<String>,
    pub rotation_kind: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ExternalKeyStore {
    pub uri_path_prefix: String,
    pub sigv4_access_key_id: String,
    pub sigv4_secret_access_key: String,
    pub xks_key_id_set: HashSet<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LimitsConfig {
    pub max_plaintext_in_base64: usize,
    pub max_aad_in_base64: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HsmCapabilitiesConfig {
    pub can_generate_iv: bool,
    pub is_zero_iv_required: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case)]
pub struct Pkcs11Config {
    pub session_pool_max_size: usize,
    pub session_pool_timeout_milli: u64,
    pub user_pin: String,
    pub session_eager_close: bool,

    // Overridable by setting the environmental variable "PKCS11_HSM_MODULE"
    pub PKCS11_HSM_MODULE: String,

    pub context_read_timeout_milli: u64,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(non_snake_case)]
pub struct Pkcs11LoggerConfig {
    // Overridable by setting the environmental variable "PKCS11_LOGGER_LIBRARY_PATH"
    pub PKCS11_LOGGER_LIBRARY_PATH: String,
    // Overridable by setting the environmental variable "PKCS11_LOGGER_LOG_FILE_PATH"
    pub PKCS11_LOGGER_LOG_FILE_PATH: String,
    // Overridable by setting the environmental variable "PKCS11_LOGGER_FLAGS"
    pub PKCS11_LOGGER_FLAGS: String,
}

#[instrument(skip_all)]
pub fn env_value(key: &str, default: &str) -> String {
    let val = env::var(key).unwrap_or_else(|_| default.to_string());
    env::set_var(key, &val);
    tracing::info!("{key}={val}");
    val
}

fn load_ciphertext_metadata(ciphertext_metadata_b64: &Option<String>) -> Vec<u8> {
    match ciphertext_metadata_b64 {
        Some(encoded) => match Base64.decode(encoded) {
            Ok(decoded) => {
                // https://github.com/marshallpierce/rust-base64/issues/189
                if &Base64.encode(&decoded) != encoded {
                    panic!("Misconfiguration: invalid base64 encoding of ciphertext metadata");
                }
                if decoded.len() > CIPHERTEXT_METATDATA_MAX_BYTE_LENGTH {
                    panic!(
                        "Misconfiguration: ciphertext metadata of length {} must not exceed {}",
                        decoded.len(),
                        CIPHERTEXT_METATDATA_MAX_BYTE_LENGTH
                    );
                }
                decoded
            }
            Err(error) => panic!(
                "Failed to base 64 decode the ciphertext metadata configured due to \"{}\"",
                error
            ),
        },
        None => vec![],
    }
}

fn load_settings() -> Settings {
    let settings_toml = env::var(XKS_PROXY_SETTINGS_TOML).unwrap_or_else(|_| {
        // Use the default specified in the bootstrap.toml
        let bootstrap_toml = fs::read_to_string(DEFAULT_BOOTSTRAP_TOML).unwrap_or_else(|_| {
            panic!(
                "failed to read from the default bootstrap toml file '{}'",
                DEFAULT_BOOTSTRAP_TOML
            )
        });

        #[derive(Debug, Deserialize)]
        #[allow(non_snake_case)]
        pub struct Bootstrap {
            // Overridable by setting the environmental variable "XKS_PROXY_SETTINGS_TOML"
            XKS_PROXY_SETTINGS_TOML: String,
        }

        let boostrap: Bootstrap = toml::from_str(bootstrap_toml.as_str()).unwrap_or_else(|_| {
            panic!("failed to load the bootstrap tom file '{}'", bootstrap_toml)
        });
        boostrap.XKS_PROXY_SETTINGS_TOML
    });

    let settings = fs::read_to_string(&settings_toml).unwrap_or_else(|_| {
        panic!(
            "failed to read from the settings toml file '{}'",
            settings_toml
        )
    });
    toml::from_str(settings.as_str()).unwrap_or_else(|_| {
        panic!(
            "failed to deserialize the settings toml file '{}'",
            settings_toml
        )
    })
}

#[cfg(test)]
mod settings_test {
    use std::collections::HashMap;
    use std::env;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Duration;

    use crate::settings::SecondaryAuth::Oso;
    use crate::settings::PKCS11_HSM_MODULE;
    use crate::{settings, SETTINGS};

    #[test]
    fn server_settings() {
        let server_config = &SETTINGS.server;
        assert!(server_config.port > 0);
        assert!(!server_config.region.is_empty());
        assert!(!server_config.service.is_empty());

        let _ip: IpAddr = server_config.ip.parse().unwrap();

        assert_eq!(
            server_config.tcp_keepalive.tcp_keepalive_secs,
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            server_config.tcp_keepalive.tcp_keepalive_interval_secs,
            Some(Duration::from_secs(1))
        );
        assert_eq!(server_config.tcp_keepalive.tcp_keepalive_retries, Some(3));
    }

    #[test]
    fn tracing_settings() {
        let tracing_config = &SETTINGS.tracing;
        if tracing_config.is_file_writer_enabled {
            assert!(!tracing_config.directory.as_ref().unwrap().is_empty());
            assert!(!tracing_config.file_prefix.as_ref().unwrap().is_empty());
            assert!(
                tracing::log::Level::from_str(tracing_config.level.as_ref().unwrap().as_str())
                    .is_ok()
            );
        }
    }

    #[test]
    fn security_and_tls_settings() {
        let security_config = &SETTINGS.security;
        if let Some(tls) = &SETTINGS.tls {
            assert!(!tls.tls_cert_pem.is_empty());
            assert!(!tls.tls_key_pem.is_empty());
            if let Some(mtls_client_ca_pem) = &tls.mtls_client_ca_pem {
                assert!(!mtls_client_ca_pem.is_empty());
            } else {
                assert!(!security_config.is_mtls_enabled);
            }
        } else {
            assert!(!security_config.is_tls_enabled);
            assert!(!security_config.is_mtls_enabled);
        }
    }

    #[test]
    fn oso_settings() {
        let security_config = &SETTINGS.security;
        let secondary_auth = security_config.secondary_auth.as_ref();
        assert_eq!(*secondary_auth.unwrap(), Oso);

        let oso_config = security_config.oso.as_ref().unwrap();
        assert_eq!(oso_config.polar_file_path, "configuration/oso.polar");
    }

    #[test]
    fn external_key_stores() {
        let external_key_stores = &SETTINGS.external_key_stores;
        assert_ne!(external_key_stores.len(), 0);
        println!("\n{external_key_stores:?}");

        let mut map = HashMap::new();
        for xks in external_key_stores {
            if map.insert(xks.uri_path_prefix.as_str(), xks).is_some() {
                panic!("uri_path_prefix '{}' must be unique", xks.uri_path_prefix);
            }
        }
        println!("external_key_stores: {map:?}\n");
    }

    #[test]
    fn env_var_override() {
        let pkcs11_config = &SETTINGS.pkcs11;
        // This test failed intermittently for some reasons; so retry 10 times to see how it goes.
        for i in 0..10 {
            env::set_var(PKCS11_HSM_MODULE, "foo");
            let val = settings::env_value(PKCS11_HSM_MODULE, &pkcs11_config.PKCS11_HSM_MODULE);
            if val == "foo" {
                println!("env_var_override succeeded upon i: {i}");
                return;
            }
        }
        panic!("failed");
    }

    #[test]
    fn env_var_default() {
        let pkcs11_config = &SETTINGS.pkcs11;
        // This test failed intermittently for some reasons; so retry 10 times to see how it goes.
        for i in 0..10 {
            env::remove_var(PKCS11_HSM_MODULE);
            let val = settings::env_value(PKCS11_HSM_MODULE, &pkcs11_config.PKCS11_HSM_MODULE);
            if val == pkcs11_config.PKCS11_HSM_MODULE {
                println!("env_var_default succeeded upon i: {i}");
                return;
            }
        }
        panic!("failed");
    }

    #[test]
    fn max_plaintext_in_base64() {
        let limits_config = &SETTINGS.limits;
        assert!(limits_config.max_plaintext_in_base64 > 4096 + 2048);
    }

    #[test]
    fn max_aad_in_base64() {
        let limits_config = &SETTINGS.limits;
        assert!(limits_config.max_aad_in_base64 > 8192 + 4096);
    }
}
