// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::str;

use axum::extract::Extension;
use axum::{extract::Path, http::StatusCode, response::IntoResponse};
use base64::engine::general_purpose::STANDARD as Base64;
use base64::Engine;
use deadpool::unmanaged::Object;
use pkcs11::types::CK_SESSION_HANDLE;
use serde::{Deserialize, Serialize};
use tracing::{info_span, Instrument};

use crate::encrypt::RequestMetadata;
use crate::settings::CIPHERTEXT_METATDATA_MAX_BYTE_LENGTH;
use crate::xks_proxy::handlers::{AadAndDigest, REQUEST_META_DATA};
use crate::xks_proxy::handlers::{DecryptInput, EncryptionAlgorithm};
use crate::xks_proxy::ErrorName::ValidationException;
use crate::xks_proxy::{handlers, remove_session_from_pool, XksProxyResult, P11_SESSION_POOL};
use crate::{DECRYPT, SETTINGS};

// Defined per XKS Proxy API spec.
#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct DecryptRequest {
    requestMetadata: RequestMetadata,
    ciphertext: String,

    // Used automatically by the rust-axum framework to reject requests if not correctly specified
    #[allow(dead_code)]
    encryptionAlgorithm: EncryptionAlgorithm,

    initializationVector: String,
    authenticationTag: String,

    ciphertextMetadata: Option<String>,
    additionalAuthenticatedData: Option<String>,
}

// Defined per XKS Proxy API spec.
#[derive(Serialize, Default)]
struct DecryptResponse {
    plaintext: String,
}

pub async fn enact(
    Extension(uri_path_prefix): Extension<String>,
    Path(key_id): Path<String>,
    handlers::Json(payload): handlers::Json<DecryptRequest>,
) -> XksProxyResult<impl IntoResponse> {
    // Create a span to include the "kmsRequestId" in tracing
    // https://docs.rs/tracing/latest/tracing/span/struct.Span.html#in-asynchronous-code
    let span = info_span!(
        DECRYPT,
        kmsRequestId = payload.requestMetadata.kmsRequestId.as_str()
    );
    async move { do_enact(uri_path_prefix, key_id, payload).await }
        .instrument(span)
        .await
}

async fn do_enact(
    uri_path_prefix: String,
    key_id: String,
    payload: DecryptRequest,
) -> XksProxyResult<impl IntoResponse> {
    tracing::info!(
        "{REQUEST_META_DATA}: {}",
        serde_json::to_string(&payload.requestMetadata).unwrap_or_else(|_| panic!(
            "failed to serialize request metadata {:?}",
            &payload.requestMetadata
        ))
    );
    super::authorize_key_usage(&uri_path_prefix, &key_id).await?;
    super::secondary_authorization(&uri_path_prefix, DECRYPT, payload.requestMetadata).await?;

    let session_pool = &P11_SESSION_POOL;
    let session_handle_object: Object<CK_SESSION_HANDLE> =
        handlers::get_or_create_session(session_pool).await?;

    // Get the secret key from the HSM
    let key_handle = match super::get_secret_key_handle(&session_handle_object, key_id.as_str()) {
        Ok(object_handle) => object_handle,
        Err(failure) => {
            return Err(super::before_bubbling_failure(
                session_handle_object,
                session_pool,
                failure,
            ))
        }
    };
    let ciphertext = super::base64_decode(&payload.ciphertext, "ciphertext")?;
    let mut iv = super::base64_decode(&payload.initializationVector, "IV")?;
    let tag = super::base64_decode(&payload.authenticationTag, "authentication tag")?;
    let AadAndDigest {
        aad: _,
        aad_len,
        aad_digest,
    } = super::aad_and_digest(&payload.additionalAuthenticatedData)?;

    let ciphertext_metadata = sanitize_ciphertext_metadata(&payload.ciphertextMetadata)?;
    let plaintext = match super::do_decrypt(
        DecryptInput {
            ciphertext,
            iv: iv.as_mut_slice(),
            tag: tag.as_slice(),
            aad_digest,
            aad_len,
            ciphertext_metadata: ciphertext_metadata.as_slice(),
        },
        (*session_handle_object, key_handle),
        key_id.as_str(),
    )
    .await
    {
        Ok(plaintext) => plaintext,
        Err(failure) => {
            return Err(super::before_bubbling_failure(
                session_handle_object,
                session_pool,
                failure,
            ))
        }
    };

    if SETTINGS.pkcs11.session_eager_close {
        tracing::debug!("Eagerly closing pkcs11 session");
        remove_session_from_pool(session_handle_object, session_pool, false);
    }
    Ok((
        StatusCode::OK,
        axum::Json(DecryptResponse {
            plaintext: Base64.encode(plaintext),
        }),
    ))
}

fn sanitize_ciphertext_metadata(
    ciphertext_metadata_b64: &Option<String>,
) -> XksProxyResult<Vec<u8>> {
    match ciphertext_metadata_b64 {
        Some(encoded) => {
            let decoded = super::base64_decode(encoded, "ciphertextMetadata")?;
            if decoded.len() > CIPHERTEXT_METATDATA_MAX_BYTE_LENGTH {
                return Err(ValidationException.as_axum_error(format!(
                    "ciphertext metadata of length {} must not exceed {CIPHERTEXT_METATDATA_MAX_BYTE_LENGTH}",
                    decoded.len())));
            }
            Ok(decoded)
        }
        None => Ok(vec![]),
    }
}
