// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;

use axum::extract::Extension;
use axum::{extract::Path, http::StatusCode, response::IntoResponse};
use oso::PolarClass;
use pkcs11::types::{
    CKA_CLASS, CKA_DECRYPT, CKA_ENCRYPT, CKA_KEY_TYPE, CKA_SIGN, CKA_UNWRAP, CKA_VALUE_LEN,
    CKA_VERIFY, CKA_WRAP, CK_ATTRIBUTE, CK_KEY_TYPE, CK_ULONG,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use tracing::{info_span, Instrument};

use xks_proxy::pkcs11::pkcs11_keytype;

use crate::xks_proxy::handlers::REQUEST_META_DATA;
use crate::xks_proxy::pkcs11::P11_CONTEXT;
use crate::xks_proxy::{handlers, remove_session_from_pool, XksProxyResult, P11_SESSION_POOL};
use crate::{xks_proxy, METADATA, SETTINGS};

// Defined per XKS Proxy API spec.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PolarClass)]
#[allow(non_snake_case)]
#[allow(dead_code)]
pub struct RequestMetadata {
    #[polar(attribute)]
    pub awsPrincipalArn: String,
    #[polar(attribute)]
    pub kmsOperation: String,
    pub kmsRequestId: String,
    #[polar(attribute)]
    pub awsSourceVpc: Option<String>,
    #[polar(attribute)]
    pub awsSourceVpce: Option<String>,
    #[polar(attribute)]
    pub kmsKeyArn: Option<String>,
    #[polar(attribute)]
    pub kmsViaService: Option<String>,
}

// Defined per XKS Proxy API spec.
#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct GetKeyMetadataRequest {
    requestMetadata: RequestMetadata,
}

// Defined per XKS Proxy API spec.
#[derive(Serialize, Debug)]
#[allow(clippy::upper_case_acronyms)]
enum KeyUsage {
    ENCRYPT,
    DECRYPT,
    SIGN,
    VERIFY,
    WRAP,
    UNWRAP,
}

// Defined per XKS Proxy API spec.
#[derive(Serialize, Default)]
#[allow(non_snake_case)]
struct KeyMetadataResponse {
    keySpec: String,
    keyUsage: Vec<KeyUsage>,
    keyStatus: String,
}

pub async fn enact(
    Extension(uri_path_prefix): Extension<String>,
    Path(key_id): Path<String>,
    handlers::Json(payload): handlers::Json<GetKeyMetadataRequest>,
) -> XksProxyResult<impl IntoResponse> {
    // Create a span to include the "kmsRequestId" in tracing
    // https://docs.rs/tracing/latest/tracing/span/struct.Span.html#in-asynchronous-code
    let span = info_span!(
        METADATA,
        kmsRequestId = payload.requestMetadata.kmsRequestId.as_str()
    );
    async move { do_enact(uri_path_prefix, key_id, payload).await }
        .instrument(span)
        .await
}

async fn do_enact(
    uri_path_prefix: String,
    key_id: String,
    payload: GetKeyMetadataRequest,
) -> XksProxyResult<impl IntoResponse> {
    tracing::info!(
        "{REQUEST_META_DATA}: {}",
        serde_json::to_string(&payload.requestMetadata).unwrap_or_else(|_| panic!(
            "failed to serialize request metadata {:?}",
            &payload.requestMetadata
        ))
    );
    super::authorize_key_usage(&uri_path_prefix, &key_id).await?;
    super::secondary_authorization(&uri_path_prefix, METADATA, payload.requestMetadata).await?;

    let session_pool = &P11_SESSION_POOL;
    let session_handle_object = handlers::get_or_create_session(session_pool).await?;

    let mut template = vec![
        CK_ATTRIBUTE::new(CKA_CLASS),
        CK_ATTRIBUTE::new(CKA_KEY_TYPE),
        CK_ATTRIBUTE::new(CKA_VALUE_LEN),
        CK_ATTRIBUTE::new(CKA_ENCRYPT),
        CK_ATTRIBUTE::new(CKA_DECRYPT),
        CK_ATTRIBUTE::new(CKA_SIGN),
        CK_ATTRIBUTE::new(CKA_VERIFY),
        CK_ATTRIBUTE::new(CKA_WRAP),
        CK_ATTRIBUTE::new(CKA_UNWRAP),
    ];

    let key_class = 0;
    let key_type = 0;
    let key_size = 0;

    let can_encrypt = 0;
    let can_decrypt = 0;
    let can_sign = 0;
    let can_verify = 0;
    let can_wrap = 0;
    let can_unwrap = 0;

    let mut i = 0;
    template[i].set_ck_ulong(&key_class);
    i += 1;
    template[i].set_ck_ulong(&key_type);
    i += 1;
    template[i].set_ck_ulong(&key_size);
    i += 1;

    template[i].set_bool(&can_encrypt);
    i += 1;
    template[i].set_bool(&can_decrypt);
    i += 1;
    template[i].set_bool(&can_sign);
    i += 1;
    template[i].set_bool(&can_verify);
    i += 1;
    template[i].set_bool(&can_wrap);
    i += 1;
    template[i].set_bool(&can_unwrap);

    let key_handle =
        match super::get_secret_key_handle(session_handle_object.deref(), key_id.as_str()) {
            Ok(object_handle) => object_handle,
            Err(failure) => {
                return Err(super::before_bubbling_failure(
                    session_handle_object,
                    session_pool,
                    failure,
                ))
            }
        };

    if let Err(pkcs11_error) =
        P11_CONTEXT
            .read()
            .get_attribute_value(*session_handle_object, key_handle, &mut template)
    {
        return Err(super::before_bubbling_failure(
            session_handle_object,
            session_pool,
            xks_proxy::handlers::pkcs11_to_xksproxy_error(pkcs11_error),
        ));
    }

    let mut usages = Vec::new();
    if can_encrypt == 1 {
        usages.push(KeyUsage::ENCRYPT);
    }
    if can_decrypt == 1 {
        usages.push(KeyUsage::DECRYPT);
    }
    if can_sign == 1 {
        usages.push(KeyUsage::SIGN);
    }
    if can_verify == 1 {
        usages.push(KeyUsage::VERIFY);
    }
    if can_wrap == 1 {
        usages.push(KeyUsage::WRAP);
    }
    if can_unwrap == 1 {
        usages.push(KeyUsage::UNWRAP);
    }

    if SETTINGS.pkcs11.session_eager_close {
        tracing::debug!("Eagerly closing pkcs11 session");
        remove_session_from_pool(session_handle_object, session_pool, false);
    }

    Ok((
        StatusCode::OK,
        axum::Json(KeyMetadataResponse {
            keySpec: keyspec(key_type, key_size),
            keyUsage: usages,
            keyStatus: "ENABLED".to_owned(),
        }),
    ))
}

fn keyspec(key_type: CK_KEY_TYPE, key_byte_size: CK_ULONG) -> String {
    let pkcs11_keytype_name = pkcs11_keytype(key_type);
    let keytype_name = &pkcs11_keytype_name["CKK_".len()..];
    format!("{keytype_name}_{}", key_byte_size << 3)
}

#[cfg(test)]
mod pkcs11_test {
    use pkcs11::types::{CKK_AES, CKK_RSA};

    use crate::get_key_meta_data::keyspec;

    #[test]
    fn aes_256_keyspec() {
        assert_eq!("AES_256", keyspec(CKK_AES, 32));
    }

    #[test]
    fn rsa_1024_keyspec() {
        assert_eq!("RSA_1024", keyspec(CKK_RSA, 128));
    }
}
