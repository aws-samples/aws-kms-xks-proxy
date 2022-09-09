// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use axum::extract::Extension;
use axum::{http::StatusCode, response::IntoResponse};
use oso::PolarClass;
use pkcs11::types::{CK_SLOT_ID, CK_TOKEN_INFO};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use tracing::{info_span, instrument, Instrument};

use crate::xks_proxy::handlers::pkcs11_to_xksproxy_error;
use crate::xks_proxy::handlers::REQUEST_META_DATA;
use crate::xks_proxy::pkcs11::{
    pkcs11_context_read_timeout_error, pkcs11_error_string, P11_CONTEXT,
};
use crate::xks_proxy::{
    handlers, is_ckr_device_error, reset_p11_context, XksProxyResult, SETTINGS,
};
use crate::HEALTH;

// Defined per XKS Proxy API spec.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PolarClass)]
#[allow(non_snake_case)]
#[allow(dead_code)]
pub struct RequestMetadata {
    kmsRequestId: String,
    #[polar(attribute)]
    kmsOperation: String,
}

// Defined per XKS Proxy API spec.
#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct GetHealthStatusRequest {
    requestMetadata: RequestMetadata,
}

// Defined per XKS Proxy API spec.
#[derive(Serialize)]
#[allow(non_snake_case)]
struct EkmFleetDetails {
    id: String,
    model: String,
    healthStatus: String,
}

// Defined per XKS Proxy API spec.
#[derive(Serialize)]
#[allow(non_snake_case)]
struct GetHealthStatusResponse {
    xksProxyFleetSize: u16,
    xksProxyVendor: String,
    xksProxyModel: String,
    ekmVendor: String,
    ekmFleetDetails: Vec<EkmFleetDetails>,
}

#[instrument]
async fn get_token_info() -> XksProxyResult<CK_TOKEN_INFO> {
    let slots_ids = do_get_slot_list().await.map_err(|pkcs11_error| {
        tracing::warn!(
            "Failed in getting slot list due to {:?}",
            pkcs11_error_string(&pkcs11_error)
        );
        if is_ckr_device_error(&pkcs11_error) {
            reset_p11_context();
        }
        pkcs11_to_xksproxy_error(pkcs11_error)
    })?;

    let slot_id = slots_ids.first().ok_or_else(|| {
        pkcs11_to_xksproxy_error(pkcs11::errors::Error::Module("No slot available"))
    })?;

    do_get_token_info(slot_id).await.map_err(|pkcs11_error| {
        tracing::warn!(
            "Failed in getting token info due to {:?}",
            pkcs11_error_string(&pkcs11_error)
        );
        if is_ckr_device_error(&pkcs11_error) {
            reset_p11_context();
        }
        pkcs11_to_xksproxy_error(pkcs11_error)
    })
}

async fn do_get_slot_list() -> Result<Vec<CK_SLOT_ID>, pkcs11::errors::Error> {
    // This function allows the read lock to get dropped immediately after use
    if let Some(ctx_read_guard) = P11_CONTEXT.try_read_for(Duration::from_millis(
        SETTINGS.pkcs11.context_read_timeout_milli,
    )) {
        Ok(ctx_read_guard.get_slot_list(false)?)
    } else {
        Err(pkcs11_context_read_timeout_error())
    }
}

async fn do_get_token_info(slot_id: &CK_SLOT_ID) -> Result<CK_TOKEN_INFO, pkcs11::errors::Error> {
    // This function allows the read lock to get dropped immediately after use
    if let Some(ctx_read_guard) = P11_CONTEXT.try_read_for(Duration::from_millis(
        SETTINGS.pkcs11.context_read_timeout_milli,
    )) {
        Ok(ctx_read_guard.get_token_info(*slot_id)?)
    } else {
        Err(pkcs11_context_read_timeout_error())
    }
}

pub async fn enact(
    Extension(uri_path_prefix): Extension<String>,
    handlers::Json(payload): handlers::Json<GetHealthStatusRequest>,
) -> XksProxyResult<impl IntoResponse> {
    // Create a span to include the "kmsRequestId" in tracing
    // https://docs.rs/tracing/latest/tracing/span/struct.Span.html#in-asynchronous-code
    let span = info_span!(
        HEALTH,
        kmsRequestId = payload.requestMetadata.kmsRequestId.as_str()
    );
    do_enact(uri_path_prefix, payload).instrument(span).await
}

async fn do_enact(
    uri_path_prefix: String,
    payload: GetHealthStatusRequest,
) -> XksProxyResult<impl IntoResponse> {
    tracing::info!(
        "{REQUEST_META_DATA}: {}",
        serde_json::to_string(&payload.requestMetadata).unwrap_or_else(|_| panic!(
            "failed to serialize request metadata {:?}",
            &payload.requestMetadata
        ))
    );
    super::secondary_authorization(&uri_path_prefix, HEALTH, payload.requestMetadata).await?;
    let token_info = get_token_info().await?;
    let firmware_version = token_info.firmwareVersion;
    let hardware_version = token_info.hardwareVersion;

    let model = token_info.model;
    let label = token_info.label;
    let manufacturer_id = token_info.manufacturerID;
    let serial_number = token_info.serialNumber;

    // Could be useful in the future to include these info in the response.
    // let rw_session_count = token_info.ulRwSessionCount;
    // let flags = token_info.flags;
    // let session_count = token_info.ulSessionCount;

    tracing::trace!("token_info: {:?}", token_info);
    let response = GetHealthStatusResponse {
        xksProxyFleetSize: 1,
        xksProxyVendor: "AWS-KMS".to_string(),
        xksProxyModel: "RustXksProxy".to_string(),
        ekmVendor: format!("{} (serial number: {})", manufacturer_id, serial_number),
        ekmFleetDetails: vec![EkmFleetDetails {
            id: label.to_string(),
            model: format!(
                "{} (firmware version: {}.{}, hardware version: {}.{})",
                model,
                firmware_version.major,
                firmware_version.minor,
                hardware_version.major,
                hardware_version.minor
            ),
            healthStatus: "ACTIVE".to_owned(),
        }],
    };

    Ok((StatusCode::OK, axum::Json(response)))
}
