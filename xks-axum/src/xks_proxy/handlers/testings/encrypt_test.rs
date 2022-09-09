// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;
use std::mem;
use std::path::PathBuf;

use pkcs11::types::{
    CKF_RW_SESSION, CKF_SERIAL_SESSION, CKM_AES_GCM, CKU_USER, CK_GCM_PARAMS, CK_GCM_PARAMS_PTR,
    CK_MECHANISM, CK_VOID_PTR,
};
use pkcs11::Ctx;

use crate::xks_proxy;
use crate::xks_proxy::pkcs11::pkcs11_error_string;

// This was used to test cloudhsm due to CKR_FUNCTION_FAILED.  The solution was to run
//     sudo /opt/cloudhsm/bin/configure-pkcs11 --disable-key-availability-check
// This code is kept in case similar test is needed in the future for debugging purposes.
// #[test]
#[allow(dead_code)]
fn test_encrypt_init() {
    let path_buf = PathBuf::from("/opt/cloudhsm/lib/libcloudhsm_pkcs11.so");
    let ctx = Ctx::new_and_initialize(path_buf).unwrap();
    let slot_ids = ctx.get_slot_list(false).unwrap();
    println!("slot_ids: {:?}", slot_ids);

    let user_pin = "<username>:<pin>"; // Replace this as needed
    let slot_id = *slot_ids.first().unwrap();
    let session_handle = ctx
        .open_session(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)
        .unwrap();
    ctx.login(session_handle, CKU_USER, Some(user_pin)).unwrap();
    let object_handle = xks_proxy::handlers::get_secret_key_handle(&session_handle, "foo").unwrap();
    println!("object_handle: {object_handle}");

    let mut iv = vec![0; 12];
    let mut aad = "some aad".as_bytes().to_vec();
    let bit_len = 0;
    let mut gcm_params = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len().try_into().unwrap(),
        ulIvBits: bit_len,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: aad.len().try_into().unwrap(),
        ulTagBits: 16 * 8,
    };
    println!("gcm_params {:?}", &gcm_params);

    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: &mut gcm_params as CK_GCM_PARAMS_PTR as CK_VOID_PTR,
        ulParameterLen: mem::size_of_val(&gcm_params).try_into().unwrap(),
    };
    println!("mechanism {:?}", &mechanism);

    if let Err(pkcs11_err) = ctx.encrypt_init(session_handle, &mechanism, object_handle) {
        let err_str = pkcs11_error_string(&pkcs11_err);
        println!("calling ctx.get_session_info");
        if let Ok(session_info) = ctx.get_session_info(session_handle) {
            println!("ulDeviceError: {}", session_info.ulDeviceError);
            println!("session_info: {:?}", session_info);
        }
        println!("Failed to encrypt with {:?} due to {err_str}", &mechanism);
    } else {
        println!("encrypt_init succeeded");
    }
}
