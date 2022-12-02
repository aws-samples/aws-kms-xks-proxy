// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate pkcs11 as rust_pkcs11;
use std::time::Duration;

use deadpool::unmanaged::{Object, Pool, PoolConfig};
use http::StatusCode;
use lazy_static::lazy_static;
use rust_pkcs11::types::CK_SESSION_HANDLE;
use serde_derive::Serialize;
use tracing::instrument;

use crate::settings::SETTINGS;
use crate::xks_proxy;
use crate::xks_proxy::pkcs11::{
    is_ckr_device_error, is_ckr_fatal, pkcs11_context_read_timeout_msg, pkcs11_error_string,
    P11_CONTEXT,
};

pub mod handlers;
pub mod pkcs11;
pub mod sigv4;

type XksProxyResult<T> = Result<T, (StatusCode, axum::Json<xks_proxy::Error>)>;

lazy_static! {
    static ref P11_SESSION_POOL: Pool<CK_SESSION_HANDLE> = {
        let pkcs11 = &super::settings::SETTINGS.pkcs11;
        let config = PoolConfig {
            max_size: pkcs11.session_pool_max_size,
            timeout: Some(std::time::Duration::from_millis(
                pkcs11.session_pool_timeout_milli,
            )),
            runtime: Some(deadpool::Runtime::Tokio1),
        };
        Pool::from_config(&config)
    };
}

// Defined per XKS Proxy API spec.
#[derive(Clone, Debug, Serialize)]
#[allow(clippy::enum_variant_names)]
pub enum ErrorName {
    ValidationException,

    #[allow(dead_code)]
    InvalidStateException,

    InvalidCiphertextException,

    #[allow(dead_code)]
    InvalidKeyUsageException,

    AuthenticationFailedException,
    AccessDeniedException,
    KeyNotFoundException,
    InvalidUriPathException,
    UnsupportedOperationException,

    #[allow(dead_code)]
    DependencyTimeoutException,

    InternalException,
}

impl ErrorName {
    fn status_code(&self) -> StatusCode {
        match *self {
            ErrorName::ValidationException
            | ErrorName::InvalidStateException
            | ErrorName::InvalidCiphertextException
            | ErrorName::InvalidKeyUsageException => StatusCode::BAD_REQUEST,
            ErrorName::AuthenticationFailedException => StatusCode::UNAUTHORIZED,
            ErrorName::AccessDeniedException => StatusCode::FORBIDDEN,
            ErrorName::KeyNotFoundException | ErrorName::InvalidUriPathException => {
                StatusCode::NOT_FOUND
            }
            ErrorName::UnsupportedOperationException => StatusCode::NOT_IMPLEMENTED,
            ErrorName::DependencyTimeoutException => StatusCode::SERVICE_UNAVAILABLE,
            ErrorName::InternalException => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn as_axum_error_impl(
        &self,
        error_message: String,
        pkcs11_error: Option<rust_pkcs11::errors::Error>,
    ) -> (StatusCode, axum::Json<Error>) {
        tracing::debug!(error_message);
        (
            self.status_code(),
            axum::Json(Error {
                errorName: self.clone(),
                pkcs11_error,
            }),
        )
    }

    pub fn as_axum_pkcs11_error(
        &self,
        error_message: String,
        pkcs11_error: rust_pkcs11::errors::Error,
    ) -> (StatusCode, axum::Json<Error>) {
        self.as_axum_error_impl(error_message, Some(pkcs11_error))
    }

    pub fn as_axum_error(&self, error_message: String) -> (StatusCode, axum::Json<Error>) {
        self.as_axum_error_impl(error_message, None)
    }
}

// Defined per XKS Proxy API spec.
#[allow(non_snake_case)]
#[derive(Debug, Serialize)]
pub struct Error {
    pub errorName: ErrorName,

    #[serde(skip)]
    pub pkcs11_error: Option<rust_pkcs11::errors::Error>,
}

#[instrument(skip_all)]
fn add_session_to_pool(session_handle: CK_SESSION_HANDLE, pool: &Pool<CK_SESSION_HANDLE>) {
    if let Err(pool_error) = pool.try_add(session_handle) {
        tracing::warn!(
            "Failed to add newly created pkcs11 session to the pool: {:?}",
            pool_error
        );
    }
    tracing::info!("pkcs11 session pool status: {:?}", pool.status());
}

// !!WARNING!!  All read locks acquired on P11_CONTEXT prior to calling this function must be dropped,
// or else it will cause dead lock.
#[instrument(skip_all)]
fn remove_session_from_pool_on_error(
    session_handle_object: Object<CK_SESSION_HANDLE>,
    pool: &Pool<CK_SESSION_HANDLE>,
    pkcs11_err: &rust_pkcs11::errors::Error,
) {
    let is_ckr_fatal = is_ckr_fatal(pkcs11_err);
    tracing::warn!(
        is_ckr_fatal,
        "Removing pkcs11 session from pool due to {pkcs11_err}"
    );
    remove_session_from_pool(session_handle_object, pool, is_ckr_device_error(pkcs11_err))
}

// !!WARNING!!  All read locks acquired on P11_CONTEXT prior to calling this function must be dropped,
// or else it will cause dead lock.
#[instrument(skip_all)]
fn remove_session_from_pool(
    session_handle_object: Object<CK_SESSION_HANDLE>,
    pool: &Pool<CK_SESSION_HANDLE>,
    is_device_error: bool,
) {
    do_close_session(*session_handle_object);
    let _ = Object::take(session_handle_object);
    let status = pool.status();
    tracing::info!("pool status after session removal: {:?}", status);
    if is_device_error && status.size == 0 {
        reset_p11_context();
    }
}

// !!WARNING!!  All read locks acquired on P11_CONTEXT prior to calling this function must be dropped,
// or else it will cause dead lock.
#[instrument]
fn reset_p11_context() {
    // We don't need to care about timing out on acquiring the write lock,
    // since the HSM is in a non-functional state anyway.
    tracing::warn!("Resetting pkcs11 context due to device failure.  Acquiring a write lock ...");
    let mut ctx_write_guard = P11_CONTEXT.write();
    tracing::info!("Write lock acquired.  Clearing the pkcs11 session pool ...");

    // Clear the session pool.
    let pool: &Pool<CK_SESSION_HANDLE> = &P11_SESSION_POOL;
    while pool.status().size > 0 {
        tracing::info!(
            "Removing pkcs11 session entries from pool of size {}",
            pool.status().size
        );
        if let Err(pool_error) = pool.try_remove() {
            tracing::warn!("error in removing pkcs11 session pool entry: {pool_error}",);
        }
    }
    tracing::info!("Cleared pkcs11 session pool.  Finalizing existing pkcs11 context ...");
    // Technically there could be race condition, i.e. incoming requests that cause new entries to be added to the pool,
    // but we don't need to care. Why? Because operations on those sessions would immediately fail which in turn
    // would lead to those entries being immediately removed.
    if let Err(pkcs11_error) = ctx_write_guard.finalize() {
        tracing::error!(
            "Failed to finalize pkcs11 context due to {}",
            pkcs11_error_string(&pkcs11_error)
        );
    }
    tracing::warn!("Creating and initializing a new pkcs11 context");
    *ctx_write_guard = unsafe { pkcs11::new_and_initialize() };
    tracing::info!("Done resetting pkcs11 context");
}

fn do_close_session(session_handle: CK_SESSION_HANDLE) {
    // This function allows the read lock to get dropped immediately after use
    tracing::warn!("Closing pkcs11 session {session_handle}");
    if let Some(ctx_read_guard) = P11_CONTEXT.try_read_for(Duration::from_millis(
        SETTINGS.pkcs11.context_read_timeout_milli,
    )) {
        if let Err(pkcs11_error) = ctx_read_guard.close_session(session_handle) {
            tracing::warn!(
                "Failed to close pkcs11 session due to {}",
                pkcs11::pkcs11_error_string(&pkcs11_error)
            );
        }
    } else {
        tracing::warn!("{} when closing session", pkcs11_context_read_timeout_msg());
    }
}
