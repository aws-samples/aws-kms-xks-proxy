// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;
use std::fmt::Debug;
use std::mem;
use std::time::Duration;

use axum::extract::rejection::JsonRejection;
use axum::extract::FromRequest;
// use axum::extract::{FromRequest, RequestParts};
use axum::body::HttpBody;
use axum::{async_trait, BoxError};
use deadpool::unmanaged::{Object, Pool};
use http::{Request, StatusCode};
use oso::ToPolar;
use pkcs11::types::{
    CKA_CLASS, CKA_LABEL, CKA_TOKEN, CKM_AES_GCM, CKO_SECRET_KEY, CKR_DATA_INVALID,
    CKR_DATA_LEN_RANGE, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_KEY_FUNCTION_NOT_PERMITTED, CK_ATTRIBUTE, CK_BYTE,
    CK_GCM_PARAMS, CK_GCM_PARAMS_PTR, CK_MECHANISM, CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_TRUE,
    CK_ULONG, CK_VOID_PTR,
};
use ring::digest;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use tracing::instrument;

use xks_proxy::{sigv4, ErrorName};

use crate::settings::{SecondaryAuth, SETTINGS};
use crate::xks_proxy;
use crate::xks_proxy::handlers::oso_auth::OSO;
use crate::xks_proxy::pkcs11::{pkcs11_context_read_timeout_msg, pkcs11_error_string};
use crate::xks_proxy::ErrorName::{
    AccessDeniedException, InternalException, InvalidCiphertextException, InvalidKeyUsageException,
    InvalidStateException, KeyNotFoundException, ValidationException,
};
use crate::xks_proxy::{Error, XksProxyResult};

use super::pkcs11::{is_ckr_fatal, P11_CONTEXT};

pub mod decrypt;
pub mod encrypt;

pub mod get_health_status;
pub mod get_key_meta_data;
mod oso_auth;

const AES_GCM_IV_BYTE_SIZE: CK_ULONG = 12;

const AES_GCM_TAG_BYTE_SIZE: CK_ULONG = 16;
const AES_GCM_TAG_BIT_SIZE: CK_ULONG = AES_GCM_TAG_BYTE_SIZE << 3;

const REQUEST_META_DATA: &str = "requestMetadata";

// Defined per XKS Proxy API spec.
// Supported Encryption Algorithms
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
pub enum EncryptionAlgorithm {
    AES_GCM,
}

fn find_secret_key(
    session_handle: &CK_SESSION_HANDLE,
    label: &str,
) -> Result<CK_OBJECT_HANDLE, pkcs11::errors::Error> {
    let template = vec![
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&CKO_SECRET_KEY),
        CK_ATTRIBUTE::new(CKA_LABEL).with_string(label),
        CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&CK_TRUE),
    ];
    // Note the read lock gets dropped immediately after use
    if let Some(ctx_read_guard) = P11_CONTEXT.try_read_for(Duration::from_millis(
        SETTINGS.pkcs11.context_read_timeout_milli,
    )) {
        ctx_read_guard.find_objects_init(*session_handle, &template)?;
        let obj_handles = ctx_read_guard.find_objects(*session_handle, 1)?;
        let len = obj_handles.len();
        if len != 1 {
            tracing::warn!(
                "Unable to uniquely identify the secret key {} with {} objects found",
                label,
                len
            );
            return Err(pkcs11::errors::Error::InvalidInput(
                "Unable to uniquely identify the secret key",
            ));
        }
        let object_handle = obj_handles
            .first()
            .expect("Bug: unable to return the first object from a vector of one element!");
        // Without calling find_objects_final it could cause CKR_OPERATION_ACTIVE for example in SoftHSMv2
        ctx_read_guard.find_objects_final(*session_handle)?;
        Ok(*object_handle)
    } else {
        Err(xks_proxy::pkcs11::pkcs11_context_read_timeout_error())
    }
}

fn sha256_then_b64(data: &[u8]) -> String {
    let digest = digest::digest(&digest::SHA256, data);
    let b64 = base64::encode(digest.as_ref());
    b64
}

fn sha256(data: &[u8], _label: &str) -> Vec<u8> {
    let digest = digest::digest(&digest::SHA256, data);
    digest.as_ref().to_vec()
}

fn base64_decode(encoded: &str, label: &str) -> XksProxyResult<Vec<u8>> {
    base64::decode(encoded).map_err(|decode_error| {
        ValidationException.as_axum_error(format!(
            "Failed to base64 decode the {label} of {} bytes with error: {decode_error:?}",
            encoded.len(),
        ))
    })
}

pub(crate) fn get_secret_key_handle(
    session_handle: &CK_SESSION_HANDLE,
    xks_key_id: &str,
) -> XksProxyResult<CK_OBJECT_HANDLE> {
    find_secret_key(session_handle, xks_key_id).map_err(|pkcs11_error| {
        let error = if is_ckr_fatal(&pkcs11_error) {
            InternalException
        } else {
            KeyNotFoundException
        };
        error.as_axum_pkcs11_error(
            format!(
                "Failed to find secret key {xks_key_id} due to {}",
                pkcs11_error_string(&pkcs11_error)
            ),
            pkcs11_error,
        )
    })
}

struct DecryptInput<'a> {
    ciphertext: Vec<u8>,
    iv: &'a mut [u8],
    tag: &'a [u8],
    aad_digest: Option<Vec<u8>>,
    aad_len: u16, // 2-bytes per the API spec
    ciphertext_metadata: &'a [u8],
}

async fn do_decrypt<'a>(
    DecryptInput {
        mut ciphertext,
        iv,
        tag,
        aad_digest,
        aad_len,
        ciphertext_metadata,
    }: DecryptInput<'a>,
    (session, key_handle): (CK_SESSION_HANDLE, CK_OBJECT_HANDLE),
    key_id: &str,
) -> XksProxyResult<Vec<CK_BYTE>> {
    let is_aad_specified = aad_digest.is_some();
    // Append the authentication tag to the ciphertext
    ciphertext.append(tag.to_vec().as_mut());

    let mut full_aad = build_full_aad(aad_len, aad_digest, ciphertext_metadata);

    let mut gcm_params = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len().try_into().unwrap(),
        ulIvBits: (iv.len() << 3).try_into().unwrap(),
        pAAD: full_aad.as_mut_ptr(),
        // full_aad is small in size since it's just a SHA256 digest concatenated
        // with a length byte and the ciphertext metadata of maximum 20 bytes
        ulAADLen: full_aad.len().try_into().unwrap(),
        ulTagBits: AES_GCM_TAG_BIT_SIZE,
    };

    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: &mut gcm_params as CK_GCM_PARAMS_PTR as CK_VOID_PTR,
        ulParameterLen: mem::size_of_val(&gcm_params).try_into().unwrap(),
    };

    tracing::trace!("ctx.decrypt_init");
    // Note the read lock gets dropped immediately after use
    if let Some(ctx_read_guard) = P11_CONTEXT.try_read_for(Duration::from_millis(
        SETTINGS.pkcs11.context_read_timeout_milli,
    )) {
        if let Err(pkcs11_error) = ctx_read_guard.decrypt_init(session, &mechanism, key_handle) {
            let (error_name, pkcs11_errmsg) = decrypt_pkcs11_to_http_error(&pkcs11_error);
            return Err(error_name.as_axum_pkcs11_error(
                format!(
                    "Failed to decrypt with {:?} due to {pkcs11_errmsg}",
                    &mechanism
                ),
                pkcs11_error,
            ));
        }

        tracing::trace!("ctx.decrypt");
        ctx_read_guard
            .decrypt(session, &ciphertext)
            .map_err(|pkcs11_error| {
                on_pkcs11_decrypt_error(
                    pkcs11_error,
                    ciphertext.len(),
                    is_aad_specified,
                    aad_len.try_into().unwrap(),
                    key_id,
                )
            })
    } else {
        Err(context_read_timeout_error())
    }
}

/// Builds the full AAD before sending to the HSM:
/// ```
///   <2-byte AAD Length in big-endian format> || [<Digest of Input AAD> ||] <1-byte Ciphertext Metadata Length> [|| <Ciphertext Metadata>]
/// ```
fn build_full_aad(
    aad_len: u16, // length of the input AAD from the http request
    aad_digest: Option<Vec<u8>>,
    ciphertext_metadata: &[u8],
) -> Vec<u8> {
    let mut full_aad: Vec<u8> = Vec::new();
    // Always append a 2-byte length of the original AAD, even when the input AAD is absent
    full_aad.extend_from_slice(&aad_len.to_be_bytes());
    if let Some(mut bytes) = aad_digest {
        full_aad.append(&mut bytes);
    }
    // Always append a 1-byte length of the ciphertextMetadata, even when the input ciphertextMetadata is absent
    let ciphertext_metadata_len: u8 = ciphertext_metadata.len().try_into().unwrap();
    full_aad.push(ciphertext_metadata_len);
    full_aad.extend_from_slice(ciphertext_metadata);
    full_aad
}

fn context_read_timeout_error() -> (StatusCode, axum::Json<xks_proxy::Error>) {
    InternalException.as_axum_error(pkcs11_context_read_timeout_msg())
}

fn on_pkcs11_decrypt_error(
    pkcs11_error: pkcs11::errors::Error,
    ciphertext_len: usize,
    is_aad_specified: bool,
    aad_len: usize,
    key_id: &str,
) -> (StatusCode, axum::Json<xks_proxy::Error>) {
    let aad_msg = if is_aad_specified {
        format!("with AAD of {aad_len} bytes")
    } else {
        "without any AAD".to_string()
    };

    let (error_name, pkcs11_errmsg) = decrypt_pkcs11_to_http_error(&pkcs11_error);

    error_name.as_axum_pkcs11_error(
        format!(
            "Failed to decrypt ciphertext of {ciphertext_len} bytes {aad_msg} using key id {key_id} due to {pkcs11_errmsg}",
        ),
        pkcs11_error,
    )
}

async fn authorize_key_usage(uri_path_prefix: &str, key_id: &str) -> XksProxyResult<()> {
    let xks = sigv4::XKSS.get(uri_path_prefix);

    // Defend against the theoretically impossible condition of missing XKS configuration:
    // The axum framework should have rejected the request before the execution gets here.
    let &xks = xks.ok_or_else(|| {
        InternalException.as_axum_error(format!(
            "Missing external key store configuration for {uri_path_prefix}"
        ))
    })?;

    if !xks.xks_key_id_set.contains(&key_id.to_string()) {
        return Err(KeyNotFoundException.as_axum_error(format!(
            "key_id {key_id} not found under the keystore {uri_path_prefix}"
        )));
    }

    tracing::trace!("Using key_id: {key_id} under {uri_path_prefix}");
    Ok(())
}

async fn oso_authorization<Metadata>(
    uri_path_prefix: &str,
    action: &str,
    metadata: Metadata,
) -> XksProxyResult<()>
where
    Metadata: Debug + ToPolar,
{
    match OSO.is_allowed(uri_path_prefix, action, metadata) {
        Ok(true) => Ok(()),
        Ok(false) => Err(AccessDeniedException
            .as_axum_error("Access denied by secondary authorization".to_string())),
        Err(oso_error) => Err(InvalidStateException.as_axum_error(format!(
            "Error occurred in secondary authorization: {oso_error:?}"
        ))),
    }
}

async fn secondary_authorization<Metadata>(
    uri_path_prefix: &str,
    action: &str,
    metadata: Metadata,
) -> XksProxyResult<()>
where
    Metadata: Debug + ToPolar,
{
    match &SETTINGS.security.secondary_auth {
        None => (), // secondary authorization is disabled
        Some(SecondaryAuth::Oso) => oso_authorization(uri_path_prefix, action, metadata).await?,
    }
    Ok(())
}

// Used to remove pkcs11 session from the pool if the failure is related to pkcs11 operations
// !!WARNING!!  All read locks acquired on P11_CONTEXT prior to calling this function must be dropped,
// or else it will cause dead lock.
fn before_bubbling_failure(
    session_handle_object: Object<CK_SESSION_HANDLE>,
    pool: &Pool<CK_SESSION_HANDLE>,
    (status_code, error_json): (StatusCode, axum::Json<xks_proxy::Error>),
) -> (StatusCode, axum::Json<xks_proxy::Error>) {
    if let Some(pkcs11_err) = &error_json.pkcs11_error {
        let is_remove_session = if let pkcs11::errors::Error::Pkcs11(ck_rv) = pkcs11_err {
            !matches!(
                *ck_rv,
                CKR_KEY_FUNCTION_NOT_PERMITTED
                    | CKR_ENCRYPTED_DATA_INVALID
                    | CKR_ENCRYPTED_DATA_LEN_RANGE
                    | CKR_DATA_INVALID
                    | CKR_DATA_LEN_RANGE
            )
        } else {
            true
        };

        if is_remove_session {
            xks_proxy::remove_session_from_pool_on_error(session_handle_object, pool, pkcs11_err)
        }
    }
    (status_code, error_json)
}

fn pkcs11_to_xksproxy_error(
    pkcs11_error: pkcs11::errors::Error,
) -> (StatusCode, axum::Json<crate::xks_proxy::Error>) {
    let (error_name, pkcs11_errmsg) = pkcs11_to_http_error(&pkcs11_error);
    error_name.as_axum_pkcs11_error(format!("pkcs11 failure {pkcs11_errmsg}"), pkcs11_error)
}

fn pkcs11_to_http_error(pkcs11_error: &pkcs11::errors::Error) -> (ErrorName, String) {
    (
        match pkcs11_error {
            pkcs11::errors::Error::Pkcs11(CKR_KEY_FUNCTION_NOT_PERMITTED) => {
                InvalidKeyUsageException
            }
            pkcs11::errors::Error::Pkcs11(CKR_ENCRYPTED_DATA_INVALID) => InvalidCiphertextException,
            _ => InternalException,
        },
        pkcs11_error_string(pkcs11_error),
    )
}

fn decrypt_pkcs11_to_http_error(pkcs11_error: &pkcs11::errors::Error) -> (ErrorName, String) {
    (
        match pkcs11_error {
            pkcs11::errors::Error::Pkcs11(ck_rv) => {
                match *ck_rv {
                    CKR_KEY_FUNCTION_NOT_PERMITTED => InvalidKeyUsageException,
                    CKR_ENCRYPTED_DATA_INVALID
                    | CKR_ENCRYPTED_DATA_LEN_RANGE
                    // CKR_FUNCTION_FAILED is reported to be returned in nShield
                    | CKR_FUNCTION_FAILED
                    // CKR_GENERAL_ERROR during decryption, for SoftHSMv2 in particular,
                    // is most likely caused by inconsistent IV, AAD, or ciphertext.
                    | CKR_GENERAL_ERROR => InvalidCiphertextException,
                    _ => InternalException,
                }
            }
            _ => InternalException,
        },
        pkcs11_error_string(pkcs11_error),
    )
}

// Warning: this function must return the *object* from the session pool, not the de-referenced value.
// Doing otherwise would cause the object to drop out of scope and get returned to the pool after this method
// returns.  Do you see why this would be really bad?
#[instrument(skip_all)]
async fn get_or_create_session(
    pool: &Pool<CK_SESSION_HANDLE>,
) -> XksProxyResult<Object<CK_SESSION_HANDLE>> {
    tracing::trace!("Session pool status: {:?}", pool.status());
    loop {
        match pool.try_get() {
            Ok(obj) => {
                tracing::trace!(
                    "Returning an existing pkcs11 session: {:?}, pool status: {:?}",
                    obj,
                    pool.status()
                );
                return Ok(obj);
            } // existing (fast path)
            Err(pool_error) => {
                tracing::warn!(
                    "No existing session found: {:?} with pool status: {:?}",
                    pool_error,
                    pool.status()
                );
                let status = pool.status();
                if status.max_size == status.size {
                    return Err(
                        InternalException.as_axum_error("Session pool exhaustion".to_string())
                    );
                }
                match crate::xks_proxy::pkcs11::new_session() {
                    // login a new session (slow path)
                    Ok(session_handle) => {
                        tracing::info!(
                            "Adding new pkcs11 login session {session_handle} to the pool"
                        );
                        // it's ok if we can't add to the session pool
                        xks_proxy::add_session_to_pool(session_handle, pool)
                    }
                    Err(pkcs11_error) => return Err(pkcs11_to_xksproxy_error(pkcs11_error)),
                };
            }
        };
    }
}

async fn do_generate_random(
    random_length: CK_ULONG,
    session: CK_SESSION_HANDLE,
) -> XksProxyResult<Vec<CK_BYTE>> {
    P11_CONTEXT
        .read()
        .generate_random(session, random_length)
        .map_err(pkcs11_to_xksproxy_error)
}

#[derive(Default)]
struct AadAndDigest {
    aad: Option<Vec<u8>>,
    aad_len: u16,
    aad_digest: Option<Vec<u8>>,
}

/// Returns the aad (after base 64 decoding), its length, and aad digest.
fn aad_and_digest(aad_encoded: &Option<String>) -> XksProxyResult<AadAndDigest> {
    let aad = match aad_encoded {
        Some(encoded) => base64_decode(encoded, "authentication tag")?,
        _ => return Ok(AadAndDigest::default()),
    };
    let aad_len = aad.len();
    let aad_digest = Some(sha256(&aad, "aad"));
    // This implementation always does a sha256 of the AAD, even when it's empty, as long as the AAD is present.
    Ok(AadAndDigest {
        aad: Some(aad),
        aad_len: aad_len.try_into().unwrap(),
        aad_digest,
    })
}

#[cfg(test)]
pub mod testings;

// Used to customize error response upon request validation failure.
// We define our own `Json` extractor that customizes the error from `axum::Json`
// Sources:
// https://docs.rs/axum/latest/axum/extract/index.html#customizing-extractor-responses
// https://github.com/tokio-rs/axum/blob/main/axum/src/json.rs
#[derive(Debug, Clone, Copy, Default)]
pub struct Json<T>(pub T);

#[async_trait]
impl<T, S, B> FromRequest<S, B> for Json<T>
where
    T: DeserializeOwned,
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, axum::Json<Error>);

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(value) => Ok(Self(value.0)),
            Err(rejection) => {
                // convert the error from `axum::Json` into whatever we want
                Err(match rejection {
                    JsonRejection::JsonDataError(err) => {
                        ValidationException.as_axum_error(format!("Invalid JSON request: {err}"))
                    }
                    JsonRejection::MissingJsonContentType(err) => {
                        ValidationException.as_axum_error(err.to_string())
                    }
                    err => ValidationException.as_axum_error(format!("Unknown JSON error: {err}")),
                })
            }
        }
    }
}
