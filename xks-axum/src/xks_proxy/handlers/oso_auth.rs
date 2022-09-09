use lazy_static::lazy_static;
use oso::PolarClass;
use oso::{Oso, OsoError};

use crate::{encrypt, get_health_status, get_key_meta_data, SETTINGS};

// Request Metadata for encrypt or decrypt; used in polar files
#[allow(dead_code)]
type EncryptMetadata = encrypt::RequestMetadata;

// Request Metadata for get_key_meta_data; used in polar files
#[allow(dead_code)]
type GetKeyMetadata = get_key_meta_data::RequestMetadata;

// Request Metadata for get_health_status; used in polar files
#[allow(dead_code)]
type GetHealthMetadata = get_health_status::RequestMetadata;

lazy_static! {
    pub static ref OSO: Oso = oso().expect("Failed to instantiate OSO");
}

fn oso() -> Result<Oso, OsoError> {
    let mut oso = Oso::new();

    // Used by secondary auth for Encrypt or Decrypt
    oso.register_class(
        encrypt::RequestMetadata::get_polar_class_builder()
            .name(stringify!(EncryptMetadata))
            .build(),
    )?;
    // Used by secondary auth for GetKeyMetadata
    oso.register_class(
        get_key_meta_data::RequestMetadata::get_polar_class_builder()
            .name(stringify!(GetKeyMetadata))
            .build(),
    )?;
    // Used by secondary auth for GetHealthStatus
    oso.register_class(
        get_health_status::RequestMetadata::get_polar_class_builder()
            .name(stringify!(GetHealthMetadata))
            .build(),
    )?;
    let oso_config = &SETTINGS
        .security
        .oso
        .as_ref()
        .expect("Oso misconfiguration");
    let polar_file_path = &oso_config.polar_file_path;
    tracing::info!("Loading oso configuration from {polar_file_path}");
    oso.load_files(vec![polar_file_path])?;
    Ok(oso)
}

#[cfg(test)]
mod settings_test {
    use crate::xks_proxy::handlers::oso_auth::OSO;
    use crate::{encrypt, get_key_meta_data, DECRYPT, ENCRYPT, METADATA};

    #[test]
    fn test_encrypt_secondary_auth() {
        let allowed = OSO
            .is_allowed(
                "access_key_1",
                ENCRYPT,
                encrypt::RequestMetadata {
                    awsPrincipalArn: "alice".to_string(),
                    kmsOperation: "Encrypt".to_string(),
                    kmsRequestId: "".to_string(),
                    kmsKeyArn: "key123".to_string(),
                    awsSourceVpc: None,
                    awsSourceVpce: None,
                    kmsViaService: Some("ebs".to_string()),
                    // kmsViaService: None,
                },
            )
            .expect("Should be authorized");
        assert!(allowed);
    }

    #[test]
    fn test_decrypt_secondary_auth() {
        let result = OSO.is_allowed(
            "access_key_1",
            DECRYPT,
            encrypt::RequestMetadata {
                awsPrincipalArn: "bob".to_string(),
                kmsOperation: "Decrypt".to_string(),
                kmsRequestId: "".to_string(),
                kmsKeyArn: "key123".to_string(),
                awsSourceVpc: None,
                awsSourceVpce: None,
                kmsViaService: Some("ebs".to_string()),
            },
        );
        println!("decrypt {:?}", result);
    }

    #[test]
    fn test_metadata_secondary_auth() {
        let result = OSO.is_allowed(
            "access_key_1",
            METADATA,
            get_key_meta_data::RequestMetadata {
                awsPrincipalArn: "bob".to_string(),
                kmsOperation: "DescribeKey".to_string(),
                kmsKeyArn: None,
                awsSourceVpc: None,
                awsSourceVpce: None,
                kmsViaService: Some("ebs".to_string()),
                kmsRequestId: "".to_string(),
            },
        );
        println!("metadata {:?}", result);
    }
}
