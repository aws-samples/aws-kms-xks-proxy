// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate pkcs11 as rust_pkcs11;

use std::path::PathBuf;
use std::time::Duration;

use lazy_static::lazy_static;
use parking_lot::RwLock;
use rust_pkcs11::types::{
    CKF_RW_SESSION, CKF_SERIAL_SESSION, CKK_ACTI, CKK_AES, CKK_ARIA, CKK_BATON, CKK_BLOWFISH,
    CKK_CAMELLIA, CKK_CAST, CKK_CAST128, CKK_CAST3, CKK_CDMF, CKK_DES, CKK_DES2, CKK_DES3, CKK_DH,
    CKK_DSA, CKK_EC, CKK_GENERIC_SECRET, CKK_GOST28147, CKK_GOSTR3410, CKK_GOSTR3411, CKK_HOTP,
    CKK_IDEA, CKK_JUNIPER, CKK_KEA, CKK_MD5_HMAC, CKK_RC2, CKK_RC4, CKK_RC5, CKK_RIPEMD128_HMAC,
    CKK_RIPEMD160_HMAC, CKK_RSA, CKK_SECURID, CKK_SEED, CKK_SHA224_HMAC, CKK_SHA256_HMAC,
    CKK_SHA384_HMAC, CKK_SHA512_HMAC, CKK_SHA_1_HMAC, CKK_SKIPJACK, CKK_TWOFISH,
    CKK_VENDOR_DEFINED, CKK_X9_42_DH, CKR_ACTION_PROHIBITED, CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID, CKR_BUFFER_TOO_SMALL, CKR_CANCEL, CKR_CANT_LOCK,
    CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_CURVE_NOT_SUPPORTED,
    CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
    CKR_DOMAIN_PARAMS_INVALID, CKR_ENCRYPTED_DATA_INVALID, CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_EXCEEDED_MAX_ITERATIONS, CKR_FIPS_SELF_TEST_FAILED, CKR_FUNCTION_CANCELED,
    CKR_FUNCTION_FAILED, CKR_FUNCTION_NOT_PARALLEL, CKR_FUNCTION_NOT_SUPPORTED,
    CKR_FUNCTION_REJECTED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_INFORMATION_SENSITIVE,
    CKR_KEY_CHANGED, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID, CKR_KEY_INDIGESTIBLE,
    CKR_KEY_NEEDED, CKR_KEY_NOT_NEEDED, CKR_KEY_NOT_WRAPPABLE, CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT, CKR_KEY_UNEXTRACTABLE, CKR_LIBRARY_LOAD_FAILED,
    CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID, CKR_MUTEX_BAD, CKR_MUTEX_NOT_LOCKED,
    CKR_NEED_TO_CREATE_THREADS, CKR_NEW_PIN_MODE, CKR_NEXT_OTP, CKR_NO_EVENT,
    CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_OPERATION_NOT_INITIALIZED,
    CKR_PIN_EXPIRED, CKR_PIN_INCORRECT, CKR_PIN_INVALID, CKR_PIN_LEN_RANGE, CKR_PIN_LOCKED,
    CKR_PIN_TOO_WEAK, CKR_PUBLIC_KEY_INVALID, CKR_RANDOM_NO_RNG, CKR_RANDOM_SEED_NOT_SUPPORTED,
    CKR_SAVED_STATE_INVALID, CKR_SESSION_CLOSED, CKR_SESSION_COUNT, CKR_SESSION_EXISTS,
    CKR_SESSION_HANDLE_INVALID, CKR_SESSION_PARALLEL_NOT_SUPPORTED, CKR_SESSION_READ_ONLY,
    CKR_SESSION_READ_ONLY_EXISTS, CKR_SESSION_READ_WRITE_SO_EXISTS, CKR_SIGNATURE_INVALID,
    CKR_SIGNATURE_LEN_RANGE, CKR_SLOT_ID_INVALID, CKR_STATE_UNSAVEABLE, CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED,
    CKR_TOKEN_WRITE_PROTECTED, CKR_UNWRAPPING_KEY_HANDLE_INVALID, CKR_UNWRAPPING_KEY_SIZE_RANGE,
    CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_ANOTHER_ALREADY_LOGGED_IN, CKR_USER_NOT_LOGGED_IN, CKR_USER_PIN_NOT_INITIALIZED,
    CKR_USER_TOO_MANY_TYPES, CKR_USER_TYPE_INVALID, CKR_VENDOR_DEFINED, CKR_WRAPPED_KEY_INVALID,
    CKR_WRAPPED_KEY_LEN_RANGE, CKR_WRAPPING_KEY_HANDLE_INVALID, CKR_WRAPPING_KEY_SIZE_RANGE,
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT, CKU_USER, CK_KEY_TYPE, CK_RV, CK_SESSION_HANDLE,
};
use rust_pkcs11::Ctx;
use tracing::instrument;

use crate::{settings, SETTINGS};

const P11_CONTEXT_READ_FAILURE: &str = "Failed to acquire pkcs11 context";

lazy_static! {
    pub static ref P11_CONTEXT: RwLock<Ctx> = RwLock::new(
        Ctx::new_and_initialize(crate::xks_proxy::pkcs11::pkcs11_module_name())
            .expect("failed to create and initialize the pkcs11 context")
    );
}

#[instrument(skip_all)]
pub fn pkcs11_module_name() -> PathBuf {
    let pkcs11_config = &SETTINGS.pkcs11;
    // Set up environment variables for pkcs11-logger
    if let Some(pkcs11_logger_config) = &SETTINGS.pkcs11_logger {
        settings::env_value(
            settings::PKCS11_LOGGER_LIBRARY_PATH,
            &pkcs11_logger_config.PKCS11_LOGGER_LIBRARY_PATH,
        );
        settings::env_value(
            settings::PKCS11_LOGGER_LOG_FILE_PATH,
            &pkcs11_logger_config.PKCS11_LOGGER_LOG_FILE_PATH,
        );
        settings::env_value(
            settings::PKCS11_LOGGER_FLAGS,
            &pkcs11_logger_config.PKCS11_LOGGER_FLAGS,
        );
    }

    // Set up the PKCS11 HSM module.
    let path = settings::env_value(
        settings::PKCS11_HSM_MODULE,
        &pkcs11_config.PKCS11_HSM_MODULE,
    );

    let path_buf = PathBuf::from(path);
    if !path_buf.exists() {
        panic!(
            "Could not find HSM at `{}`. Set the `PKCS11_HSM_MODULE` configuration to \
       its location.",
            path_buf.display()
        );
    }
    path_buf
}

#[allow(dead_code)]
pub fn pkcs11_keytype(keytype: CK_KEY_TYPE) -> &'static str {
    match keytype {
        CKK_RSA => "CKK_RSA",
        CKK_DSA => "CKK_DSA",
        CKK_DH => "CKK_DH",
        // CKK_ECDSA is deprecated in pkcs#11 v2.11, and is the same as CKK_EC
        // CKK_ECDSA => "CKK_ECDSA",
        CKK_EC => "CKK_EC",
        CKK_X9_42_DH => "CKK_X9_42_DH",
        CKK_KEA => "CKK_KEA",
        CKK_GENERIC_SECRET => "CKK_GENERIC_SECRET",
        CKK_RC2 => "CKK_RC2",
        CKK_RC4 => "CKK_RC4",
        CKK_DES => "CKK_DES",
        CKK_DES2 => "CKK_DES2",
        CKK_DES3 => "CKK_DES3",
        CKK_CAST => "CKK_CAST",
        CKK_CAST3 => "CKK_CAST3",
        // CKK_CAST5 is deprecated in pkcs#11 v2.11, and is the same as CKK_CAST128
        // CKK_CAST5 => "CKK_CAST5",
        CKK_CAST128 => "CKK_CAST128",
        CKK_RC5 => "CKK_RC5",
        CKK_IDEA => "CKK_IDEA",
        CKK_SKIPJACK => "CKK_SKIPJACK",
        CKK_BATON => "CKK_BATON",
        CKK_JUNIPER => "CKK_JUNIPER",
        CKK_CDMF => "CKK_CDMF",
        CKK_AES => "CKK_AES",
        CKK_BLOWFISH => "CKK_BLOWFISH",
        CKK_TWOFISH => "CKK_TWOFISH",
        CKK_SECURID => "CKK_SECURID",
        CKK_HOTP => "CKK_HOTP",
        CKK_ACTI => "CKK_ACTI",
        CKK_CAMELLIA => "CKK_CAMELLIA",
        CKK_ARIA => "CKK_ARIA",
        CKK_MD5_HMAC => "CKK_MD5_HMAC",
        CKK_SHA_1_HMAC => "CKK_SHA_1_HMAC",
        CKK_RIPEMD128_HMAC => "CKK_RIPEMD128_HMAC",
        CKK_RIPEMD160_HMAC => "CKK_RIPEMD160_HMAC",
        CKK_SHA256_HMAC => "CKK_SHA256_HMAC",
        CKK_SHA384_HMAC => "CKK_SHA384_HMAC",
        CKK_SHA512_HMAC => "CKK_SHA512_HMAC",
        CKK_SHA224_HMAC => "CKK_SHA224_HMAC",
        CKK_SEED => "CKK_SEED",
        CKK_GOSTR3410 => "CKK_GOSTR3410",
        CKK_GOSTR3411 => "CKK_GOSTR3411",
        CKK_GOST28147 => "CKK_GOST28147",
        CKK_VENDOR_DEFINED => "CKK_VENDOR_DEFINED",
        _ => "unknown",
    }
}

#[allow(dead_code)]
pub fn pkcs11_strerror(err: CK_RV) -> &'static str {
    match err {
        CKR_OK => "CKR_OK",
        CKR_CANCEL => "CKR_CANCEL",
        CKR_HOST_MEMORY => "CKR_HOST_MEMORY",
        CKR_SLOT_ID_INVALID => "CKR_SLOT_ID_INVALID",
        CKR_GENERAL_ERROR => "CKR_GENERAL_ERROR",
        CKR_FUNCTION_FAILED => "CKR_FUNCTION_FAILED",
        CKR_ARGUMENTS_BAD => "CKR_ARGUMENTS_BAD",
        CKR_NO_EVENT => "CKR_NO_EVENT",
        CKR_NEED_TO_CREATE_THREADS => "CKR_NEED_TO_CREATE_THREADS",
        CKR_CANT_LOCK => "CKR_CANT_LOCK",
        CKR_ATTRIBUTE_READ_ONLY => "CKR_ATTRIBUTE_READ_ONLY",
        CKR_ATTRIBUTE_SENSITIVE => "CKR_ATTRIBUTE_SENSITIVE",
        CKR_ATTRIBUTE_TYPE_INVALID => "CKR_ATTRIBUTE_TYPE_INVALID",
        CKR_ATTRIBUTE_VALUE_INVALID => "CKR_ATTRIBUTE_VALUE_INVALID",
        CKR_ACTION_PROHIBITED => "CKR_ACTION_PROHIBITED",
        CKR_DATA_INVALID => "CKR_DATA_INVALID",
        CKR_DATA_LEN_RANGE => "CKR_DATA_LEN_RANGE",
        CKR_DEVICE_ERROR => "CKR_DEVICE_ERROR",
        CKR_DEVICE_MEMORY => "CKR_DEVICE_MEMORY",
        CKR_DEVICE_REMOVED => "CKR_DEVICE_REMOVED",
        CKR_ENCRYPTED_DATA_INVALID => "CKR_ENCRYPTED_DATA_INVALID",
        CKR_ENCRYPTED_DATA_LEN_RANGE => "CKR_ENCRYPTED_DATA_LEN_RANGE",
        CKR_FUNCTION_CANCELED => "CKR_FUNCTION_CANCELED",
        CKR_FUNCTION_NOT_PARALLEL => "CKR_FUNCTION_NOT_PARALLEL",
        CKR_FUNCTION_NOT_SUPPORTED => "CKR_FUNCTION_NOT_SUPPORTED",
        CKR_KEY_HANDLE_INVALID => "CKR_KEY_HANDLE_INVALID",
        CKR_KEY_SIZE_RANGE => "CKR_KEY_SIZE_RANGE",
        CKR_KEY_TYPE_INCONSISTENT => "CKR_KEY_TYPE_INCONSISTENT",
        CKR_KEY_NOT_NEEDED => "CKR_KEY_NOT_NEEDED",
        CKR_KEY_CHANGED => "CKR_KEY_CHANGED",
        CKR_KEY_NEEDED => "CKR_KEY_NEEDED",
        CKR_KEY_INDIGESTIBLE => "CKR_KEY_INDIGESTIBLE",
        CKR_KEY_FUNCTION_NOT_PERMITTED => "CKR_KEY_FUNCTION_NOT_PERMITTED",
        CKR_KEY_NOT_WRAPPABLE => "CKR_KEY_NOT_WRAPPABLE",
        CKR_KEY_UNEXTRACTABLE => "CKR_KEY_UNEXTRACTABLE",
        CKR_MECHANISM_INVALID => "CKR_MECHANISM_INVALID",
        CKR_MECHANISM_PARAM_INVALID => "CKR_MECHANISM_PARAM_INVALID",
        CKR_OBJECT_HANDLE_INVALID => "CKR_OBJECT_HANDLE_INVALID",
        CKR_OPERATION_ACTIVE => "CKR_OPERATION_ACTIVE",
        CKR_OPERATION_NOT_INITIALIZED => "CKR_OPERATION_NOT_INITIALIZED",
        CKR_PIN_INCORRECT => "CKR_PIN_INCORRECT",
        CKR_PIN_INVALID => "CKR_PIN_INVALID",
        CKR_PIN_LEN_RANGE => "CKR_PIN_LEN_RANGE",
        CKR_PIN_EXPIRED => "CKR_PIN_EXPIRED",
        CKR_PIN_LOCKED => "CKR_PIN_LOCKED",
        CKR_SESSION_CLOSED => "CKR_SESSION_CLOSED",
        CKR_SESSION_COUNT => "CKR_SESSION_COUNT",
        CKR_SESSION_HANDLE_INVALID => "CKR_SESSION_HANDLE_INVALID",
        CKR_SESSION_PARALLEL_NOT_SUPPORTED => "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
        CKR_SESSION_READ_ONLY => "CKR_SESSION_READ_ONLY",
        CKR_SESSION_EXISTS => "CKR_SESSION_EXISTS",
        CKR_SESSION_READ_ONLY_EXISTS => "CKR_SESSION_READ_ONLY_EXISTS",
        CKR_SESSION_READ_WRITE_SO_EXISTS => "CKR_SESSION_READ_WRITE_SO_EXISTS",
        CKR_SIGNATURE_INVALID => "CKR_SIGNATURE_INVALID",
        CKR_SIGNATURE_LEN_RANGE => "CKR_SIGNATURE_LEN_RANGE",
        CKR_TEMPLATE_INCOMPLETE => "CKR_TEMPLATE_INCOMPLETE",
        CKR_TEMPLATE_INCONSISTENT => "CKR_TEMPLATE_INCONSISTENT",
        CKR_TOKEN_NOT_PRESENT => "CKR_TOKEN_NOT_PRESENT",
        CKR_TOKEN_NOT_RECOGNIZED => "CKR_TOKEN_NOT_RECOGNIZED",
        CKR_TOKEN_WRITE_PROTECTED => "CKR_TOKEN_WRITE_PROTECTED",
        CKR_UNWRAPPING_KEY_HANDLE_INVALID => "CKR_UNWRAPPING_KEY_HANDLE_INVALID",
        CKR_UNWRAPPING_KEY_SIZE_RANGE => "CKR_UNWRAPPING_KEY_SIZE_RANGE",
        CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT => "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT",
        CKR_USER_ALREADY_LOGGED_IN => "CKR_USER_ALREADY_LOGGED_IN",
        CKR_USER_NOT_LOGGED_IN => "CKR_USER_NOT_LOGGED_IN",
        CKR_USER_PIN_NOT_INITIALIZED => "CKR_USER_PIN_NOT_INITIALIZED",
        CKR_USER_TYPE_INVALID => "CKR_USER_TYPE_INVALID",
        CKR_USER_ANOTHER_ALREADY_LOGGED_IN => "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
        CKR_USER_TOO_MANY_TYPES => "CKR_USER_TOO_MANY_TYPES",
        CKR_WRAPPED_KEY_INVALID => "CKR_WRAPPED_KEY_INVALID",
        CKR_WRAPPED_KEY_LEN_RANGE => "CKR_WRAPPED_KEY_LEN_RANGE",
        CKR_WRAPPING_KEY_HANDLE_INVALID => "CKR_WRAPPING_KEY_HANDLE_INVALID",
        CKR_WRAPPING_KEY_SIZE_RANGE => "CKR_WRAPPING_KEY_SIZE_RANGE",
        CKR_WRAPPING_KEY_TYPE_INCONSISTENT => "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
        CKR_RANDOM_SEED_NOT_SUPPORTED => "CKR_RANDOM_SEED_NOT_SUPPORTED",
        CKR_RANDOM_NO_RNG => "CKR_RANDOM_NO_RNG",
        CKR_DOMAIN_PARAMS_INVALID => "CKR_DOMAIN_PARAMS_INVALID",
        CKR_CURVE_NOT_SUPPORTED => "CKR_CURVE_NOT_SUPPORTED",
        CKR_BUFFER_TOO_SMALL => "CKR_BUFFER_TOO_SMALL",
        CKR_SAVED_STATE_INVALID => "CKR_SAVED_STATE_INVALID",
        CKR_INFORMATION_SENSITIVE => "CKR_INFORMATION_SENSITIVE",
        CKR_STATE_UNSAVEABLE => "CKR_STATE_UNSAVEABLE",
        CKR_CRYPTOKI_NOT_INITIALIZED => "CKR_CRYPTOKI_NOT_INITIALIZED",
        CKR_CRYPTOKI_ALREADY_INITIALIZED => "CKR_CRYPTOKI_ALREADY_INITIALIZED",
        CKR_MUTEX_BAD => "CKR_MUTEX_BAD",
        CKR_MUTEX_NOT_LOCKED => "CKR_MUTEX_NOT_LOCKED",
        CKR_NEW_PIN_MODE => "CKR_NEW_PIN_MODE",
        CKR_NEXT_OTP => "CKR_NEXT_OTP",
        CKR_EXCEEDED_MAX_ITERATIONS => "CKR_EXCEEDED_MAX_ITERATIONS",
        CKR_FIPS_SELF_TEST_FAILED => "CKR_FIPS_SELF_TEST_FAILED",
        CKR_LIBRARY_LOAD_FAILED => "CKR_LIBRARY_LOAD_FAILED",
        CKR_PIN_TOO_WEAK => "CKR_PIN_TOO_WEAK",
        CKR_PUBLIC_KEY_INVALID => "CKR_PUBLIC_KEY_INVALID",
        CKR_FUNCTION_REJECTED => "CKR_FUNCTION_REJECTED",
        CKR_VENDOR_DEFINED => "CKR_VENDOR_DEFINED",
        _ => "unknown",
    }
}

#[instrument]
pub fn new_session(is_login: bool) -> Result<CK_SESSION_HANDLE, rust_pkcs11::errors::Error> {
    // Note the read lock gets dropped immediately after use
    if let Some(ctx_read_guard) = P11_CONTEXT.try_read_for(Duration::from_millis(
        SETTINGS.pkcs11.context_read_timeout_milli,
    )) {
        let slot_ids = ctx_read_guard.get_slot_list(false)?;
        let user_pin = &SETTINGS.pkcs11.user_pin.as_str();
        let slot_id = *slot_ids
            .first()
            .ok_or(rust_pkcs11::errors::Error::Module("No slot available"))?;
        tracing::info!("Opening session on slot {slot_id}");
        let session_handle = ctx_read_guard.open_session(
            slot_id,
            CKF_SERIAL_SESSION | CKF_RW_SESSION,
            None,
            None,
        )?;
        if is_login {
            tracing::info!("Logging out session on slot {slot_id} before logging in");
            if let Err(pkcs11_error) = ctx_read_guard.logout(session_handle) {
                tracing::warn!(
                    "Failed to logout on slot {slot_id} due to {}.  Please ignore the first such warning after the server has started.",
                    pkcs11_error_string(&pkcs11_error)
                );
            }
            tracing::info!("Logging in session on slot {slot_id}");
            ctx_read_guard.login(session_handle, CKU_USER, Some(user_pin))?;
        }
        Ok(session_handle)
    } else {
        Err(pkcs11_context_read_timeout_error())
    }
}

pub fn pkcs11_error_string(err: &rust_pkcs11::errors::Error) -> String {
    match err {
        rust_pkcs11::errors::Error::Pkcs11(ck_rv) => pkcs11_strerror(*ck_rv).to_owned(),
        _ => err.to_string(),
    }
}

pub fn pkcs11_context_read_timeout_error() -> pkcs11::errors::Error {
    let errmsg = Box::new(pkcs11_context_read_timeout_msg());
    tracing::warn!("{errmsg}");
    pkcs11::errors::Error::Module(P11_CONTEXT_READ_FAILURE)
}

pub fn pkcs11_context_read_timeout_msg() -> String {
    format!(
        "{P11_CONTEXT_READ_FAILURE} in {} ms",
        SETTINGS.pkcs11.context_read_timeout_milli
    )
}

#[cfg(test)]
mod tests {
    extern crate pkcs11 as rust_pkcs11;

    use rust_pkcs11::types::{CKK_AES, CKK_CAST128, CKK_CAST5, CKK_EC, CKK_ECDSA, CKK_RSA};

    #[test]
    fn keytype_test() {
        assert_eq!("CKK_AES", super::pkcs11_keytype(CKK_AES));
        assert_eq!("CKK_RSA", super::pkcs11_keytype(CKK_RSA));

        assert_eq!("CKK_EC", super::pkcs11_keytype(CKK_EC));
        assert_eq!("CKK_EC", super::pkcs11_keytype(CKK_ECDSA));

        assert_eq!("CKK_CAST128", super::pkcs11_keytype(CKK_CAST128));
        assert_eq!("CKK_CAST128", super::pkcs11_keytype(CKK_CAST5));
    }
}
