// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;
use std::time::Duration;
use std::{mem, str};

use axum::extract::Extension;
use axum::{extract::Path, http::StatusCode, response::IntoResponse};
use base64;
use oso::PolarClass;
use pkcs11::types::{
    CKM_AES_GCM, CK_BYTE, CK_GCM_PARAMS, CK_GCM_PARAMS_PTR, CK_MECHANISM, CK_OBJECT_HANDLE,
    CK_SESSION_HANDLE, CK_VOID_PTR,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use tracing::{info_span, instrument, Instrument};

use crate::settings::CIPHERTEXT_METADATA;
use crate::xks_proxy::handlers::{
    build_full_aad, context_read_timeout_error, pkcs11_to_http_error, DecryptInput,
    EncryptionAlgorithm,
};
use crate::xks_proxy::handlers::{AadAndDigest, REQUEST_META_DATA};
use crate::xks_proxy::pkcs11::P11_CONTEXT;
use crate::xks_proxy::ErrorName::UnsupportedOperationException;
use crate::xks_proxy::{handlers, remove_session_from_pool, XksProxyResult, P11_SESSION_POOL};
use crate::{xks_proxy, ENCRYPT, SETTINGS};

use super::{AES_GCM_IV_BYTE_SIZE, AES_GCM_TAG_BIT_SIZE, AES_GCM_TAG_BYTE_SIZE};

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
    pub kmsKeyArn: String,
    #[polar(attribute)]
    pub awsSourceVpc: Option<String>,
    #[polar(attribute)]
    pub awsSourceVpce: Option<String>,
    #[polar(attribute)]
    pub kmsViaService: Option<String>,
}

// Defined per XKS Proxy API spec.
// Supported Ciphertext Data Integrity Value Algorithms
#[derive(Debug, Deserialize, Serialize)]
#[allow(non_camel_case_types)]
pub enum CdivAlgorithm {
    SHA_256,
}

// Defined per XKS Proxy API spec.
#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct EncryptRequest {
    requestMetadata: RequestMetadata,
    plaintext: String,

    // Used automatically by the rust-axum framework to reject requests if not correctly specified
    #[allow(dead_code)]
    encryptionAlgorithm: EncryptionAlgorithm,

    additionalAuthenticatedData: Option<String>,
    ciphertextDataIntegrityValueAlgorithm: Option<CdivAlgorithm>,
}

// Defined per XKS Proxy API spec.
#[skip_serializing_none]
#[derive(Serialize, Default)]
#[allow(non_snake_case)]
struct EncryptResponse {
    ciphertext: String,
    initializationVector: String,
    authenticationTag: String,
    ciphertextMetadata: Option<String>,
    ciphertextDataIntegrityValue: Option<String>,
}

struct PlainBlob<'a> {
    plaintext: Vec<u8>,
    aad_digest: Option<Vec<u8>>,
    aad_len: u16, // 2-bytes per the API spec
    ciphertext_metadata: &'a [u8],
}

struct CipherBlob {
    ciphertext: Vec<CK_BYTE>,
    iv: Vec<CK_BYTE>,
    tag: Vec<CK_BYTE>,
}

pub async fn enact(
    Extension(uri_path_prefix): Extension<String>,
    Path(key_id): Path<String>,
    handlers::Json(payload): handlers::Json<EncryptRequest>,
) -> XksProxyResult<impl IntoResponse> {
    // Create a span to include the "kmsRequestId" in tracing
    // https://docs.rs/tracing/latest/tracing/span/struct.Span.html#in-asynchronous-code
    let span = info_span!(
        ENCRYPT,
        kmsRequestId = payload.requestMetadata.kmsRequestId.as_str()
    );
    async move { do_enact(uri_path_prefix, key_id, payload).await }
        .instrument(span)
        .await
}

async fn do_enact(
    uri_path_prefix: String,
    key_id: String,
    payload: EncryptRequest,
) -> XksProxyResult<impl IntoResponse> {
    tracing::info!(
        "{REQUEST_META_DATA}: {}",
        serde_json::to_string(&payload.requestMetadata).unwrap_or_else(|_| panic!(
            "failed to serialize request metadata {:?}",
            &payload.requestMetadata
        ))
    );
    super::authorize_key_usage(&uri_path_prefix, &key_id).await?;
    super::secondary_authorization(&uri_path_prefix, ENCRYPT, payload.requestMetadata).await?;
    // Check size limits
    let limits_config = &SETTINGS.limits;
    check_size_limit(
        payload.plaintext.len(),
        limits_config.max_plaintext_in_base64,
        "plaintext",
    )?;
    if let Some(aad) = &payload.additionalAuthenticatedData {
        check_size_limit(aad.len(), limits_config.max_aad_in_base64, "AAD")?;
    }

    let session_pool = &P11_SESSION_POOL;
    let session_handle_object = handlers::get_or_create_session(session_pool).await?;

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

    let plaintext = super::base64_decode(&payload.plaintext, "plaintext")?;
    let AadAndDigest {
        mut aad,
        aad_len,
        aad_digest,
    } = super::aad_and_digest(&payload.additionalAuthenticatedData)?;

    // Encrypt the plaintext
    let CipherBlob {
        ciphertext,
        mut iv,
        tag,
    } = match do_encrypt(
        PlainBlob {
            plaintext,
            aad_digest: aad_digest.clone(),
            aad_len,
            ciphertext_metadata: CIPHERTEXT_METADATA.as_slice(),
        },
        (*session_handle_object, key_handle),
        key_id.as_str(),
    )
    .await
    {
        Ok(result) => result,
        Err(failure) => {
            return Err(super::before_bubbling_failure(
                session_handle_object,
                session_pool,
                failure,
            ))
        }
    };

    //  [<Input AAD> ||] [<Ciphertext Metadata> ||] <IV> || <Ciphertext> || <Authentication Tag>
    let cdiv = match payload.ciphertextDataIntegrityValueAlgorithm {
        None => None,
        Some(CdivAlgorithm::SHA_256) => {
            let mut data = Vec::new();
            if let Some(bytes) = aad.as_mut() {
                data.append(bytes);
            }
            data.extend_from_slice(CIPHERTEXT_METADATA.as_slice());
            data.append(&mut iv.clone());
            data.append(&mut ciphertext.clone());
            data.append(&mut tag.clone());
            let cdiv = super::sha256_then_b64(data.as_slice());
            tracing::trace!("Decrypt the ciphertext after the cdiv {cdiv} has been generated.");
            // Perform a decryption to provide meaningful integrity assurance.
            // This must happen after the cdiv is generated, not before; for otherwise it will break the integrity assurance.
            if let Err(failure) = super::do_decrypt(
                DecryptInput {
                    ciphertext: ciphertext.clone(),
                    iv: iv.as_mut_slice(),
                    tag: tag.as_slice(),
                    aad_digest,
                    aad_len,
                    ciphertext_metadata: CIPHERTEXT_METADATA.as_slice(),
                },
                (*session_handle_object, key_handle),
                key_id.as_str(),
            )
            .await
            {
                return Err(super::before_bubbling_failure(
                    session_handle_object,
                    session_pool,
                    failure,
                ));
            }
            Some(cdiv)
        }
    };

    if SETTINGS.pkcs11.session_eager_close {
        tracing::debug!("Eagerly closing pkcs11 session");
        remove_session_from_pool(session_handle_object, session_pool, false);
    }
    Ok((
        StatusCode::OK,
        axum::Json(EncryptResponse {
            ciphertext: base64::encode(ciphertext),
            initializationVector: base64::encode(iv),
            authenticationTag: base64::encode(tag),
            ciphertextMetadata: SETTINGS.server.ciphertext_metadata_b64.to_owned(),
            ciphertextDataIntegrityValue: cdiv,
        }),
    ))
}

#[instrument]
fn check_size_limit(len: usize, max: usize, label: &str) -> XksProxyResult<()> {
    tracing::trace!("len: {len} vs max: {max}");
    if len > max {
        return Err(UnsupportedOperationException.as_axum_error(format!(
            "{label} in base 64 with size of {len} bytes is too large.  Maximum: {max} bytes."
        )));
    };
    Ok(())
}

#[instrument(skip_all)]
async fn do_encrypt(
    PlainBlob {
        plaintext,
        aad_digest,
        aad_len,
        ciphertext_metadata,
    }: PlainBlob<'_>,
    (session_handle, key_handle): (CK_SESSION_HANDLE, CK_OBJECT_HANDLE),
    key_id: &str,
) -> XksProxyResult<CipherBlob> {
    let is_aad_specified = aad_digest.is_some();
    let can_generate_iv = SETTINGS.hsm_capabilities.can_generate_iv;
    let is_zero_iv_required = SETTINGS.hsm_capabilities.is_zero_iv_required;
    let mut iv = if !can_generate_iv {
        super::do_generate_random(AES_GCM_IV_BYTE_SIZE, session_handle).await?
    } else if is_zero_iv_required {
        vec![0; AES_GCM_IV_BYTE_SIZE.try_into().unwrap()] // this is necessary for CloudHSM
    } else {
        Vec::new()
    };

    let iv_bit_len = (iv.len() << 3).try_into().unwrap();
    tracing::trace!(
        "Using IV {} of {} bytes and {iv_bit_len} bits",
        hex::encode(&iv),
        iv.len(),
    );

    let mut full_aad = build_full_aad(aad_len, aad_digest, ciphertext_metadata);

    let mut gcm_params = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len().try_into().unwrap(),
        ulIvBits: iv_bit_len,
        pAAD: full_aad.as_mut_ptr(),
        ulAADLen: full_aad.len().try_into().unwrap(),
        ulTagBits: AES_GCM_TAG_BIT_SIZE,
    };

    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: &mut gcm_params as CK_GCM_PARAMS_PTR as CK_VOID_PTR,
        ulParameterLen: mem::size_of_val(&gcm_params).try_into().unwrap(),
    };

    tracing::trace!(
        "calling ctx.encrypt_init iv: {}, byte-len: {}, bit-len: {}",
        hex::encode(&iv),
        iv.len(),
        iv.len() << 3
    );
    do_encrypt_init(session_handle, key_handle, &mechanism)?;
    let plaintext_len = plaintext.len();
    tracing::trace!("ctx.encrypt");
    let encryption_output = {
        // This extra scope allows the read lock to get dropped immediately after use
        if let Some(ctx_read_guard) = P11_CONTEXT.try_read_for(Duration::from_millis(
            SETTINGS.pkcs11.context_read_timeout_milli,
        )) {
            match ctx_read_guard.encrypt(session_handle, plaintext.as_slice()) {
                Ok(bytes) => bytes,
                Err(pkcs11_error) => {
                    return Err(on_pkcs11_encrypt_error(
                        pkcs11_error,
                        plaintext_len,
                        is_aad_specified,
                        aad_len,
                        key_id,
                    ));
                }
            }
        } else {
            return Err(context_read_timeout_error());
        }
    };

    let ciphertext_without_tag = encryption_output[..(plaintext_len)].to_vec();
    let tag =
        encryption_output[plaintext_len..(plaintext_len + AES_GCM_TAG_BYTE_SIZE as usize)].to_vec();

    if can_generate_iv && !is_zero_iv_required {
        // This is how Luna HSM works.  Not sure about other vendors at this stage.
        tracing::trace!("Extracting IV from cipher text");
        iv = encryption_output[(plaintext_len + AES_GCM_TAG_BYTE_SIZE as usize)..].to_vec()
    }

    Ok(CipherBlob {
        ciphertext: ciphertext_without_tag,
        iv,
        tag,
    })
}

fn do_encrypt_init(
    session_handle: CK_SESSION_HANDLE,
    key_handle: CK_OBJECT_HANDLE,
    mechanism: &CK_MECHANISM,
) -> XksProxyResult<()> {
    // This function allows the read lock to get dropped immediately after use
    if let Some(ctx_read_guard) = P11_CONTEXT.try_read_for(Duration::from_millis(
        SETTINGS.pkcs11.context_read_timeout_milli,
    )) {
        // The following call always failed with CKR_FUNCTION_FAILED against CloudHSM until I did:
        //      sudo /opt/cloudhsm/bin/configure-pkcs11 --disable-key-availability-check
        if let Err(pkcs11_error) =
            ctx_read_guard.encrypt_init(session_handle, mechanism, key_handle)
        {
            let (error_name, pkcs11_errmsg) = pkcs11_to_http_error(&pkcs11_error);
            tracing::trace!("calling ctx.get_session_info");
            if let Ok(session_info) = ctx_read_guard.get_session_info(session_handle) {
                tracing::warn!("ulDeviceError: {}", session_info.ulDeviceError);
                tracing::warn!("session_info: {session_info:?}");
            }
            return Err(error_name.as_axum_pkcs11_error(
                format!(
                    "Failed to encrypt with {:?} due to {pkcs11_errmsg}",
                    &mechanism
                ),
                pkcs11_error,
            ));
        }
        Ok(())
    } else {
        Err(context_read_timeout_error())
    }
}

fn on_pkcs11_encrypt_error(
    pkcs11_error: pkcs11::errors::Error,
    plaintext_len: usize,
    is_aad_specified: bool,
    aad_len: u16,
    key_id: &str,
) -> (StatusCode, axum::Json<xks_proxy::Error>) {
    let aad_msg = if is_aad_specified {
        format!("with AAD of {aad_len} bytes")
    } else {
        "without any AAD".to_string()
    };

    let (error_name, pkcs11_errmsg) = super::pkcs11_to_http_error(&pkcs11_error);

    error_name.as_axum_pkcs11_error(
        format!(
            "Failed to encrypt plaintext of {plaintext_len} bytes {aad_msg} using key id {key_id} due to {pkcs11_errmsg}",
        ),
        pkcs11_error,
    )
}
