// Copyright 2017 Marcus Heese
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::convert::TryInto;
use std::env;
use std::path::PathBuf;

extern crate hex;
/// Tests need to be run with `RUST_TEST_THREADS=1` currently to pass.
extern crate num_traits;

use self::hex::FromHex;
use self::num_traits::Num;

use super::errors::Error;
use super::types::*;
use super::*;
use num_bigint::BigUint;

fn pkcs11_module_name() -> PathBuf {
    let default_path =
        option_env!("PKCS11_SOFTHSM2_MODULE").unwrap_or("/usr/local/lib/softhsm/libsofthsm2.so");
    let path = env::var_os("PKCS11_SOFTHSM2_MODULE").unwrap_or_else(|| default_path.into());
    let path_buf = PathBuf::from(path);

    if !path_buf.exists() {
        panic!(
      "Could not find SoftHSM2 at `{}`. Set the `PKCS11_SOFTHSM2_MODULE` environment variable to \
       its location.",
      path_buf.display());
    }

    path_buf
}

#[test]
#[serial]
fn test_str_from_blank_padded() {
    let nothing_removed = b"no padding blanks to remove";
    let trailing_blanks_removed = b"a few removed     ";
    let leading_blanks_not_removed = b"     untouched";
    let trailing_nonblanks_not_removed = b"only spaces removed\t\t\t\t";
    let invalid_utf8 = b"\xffinvalid";

    assert_eq!(
        nothing_removed,
        str_from_blank_padded(nothing_removed).as_bytes()
    );
    assert_eq!(
        b"a few removed",
        str_from_blank_padded(trailing_blanks_removed).as_bytes()
    );
    assert_eq!(
        leading_blanks_not_removed,
        str_from_blank_padded(leading_blanks_not_removed).as_bytes()
    );
    assert_eq!(
        trailing_nonblanks_not_removed,
        str_from_blank_padded(trailing_nonblanks_not_removed).as_bytes()
    );
    assert_eq!("�invalid", str_from_blank_padded(invalid_utf8));
}

#[test]
#[serial]
fn test_label_from_str() {
    let s30 = "Löwe 老虎 Léopar虎d虎aaa";
    let s32 = "Löwe 老虎 Léopar虎d虎aaaö";
    let s33 = "Löwe 老虎 Léopar虎d虎aaa虎";
    let s34 = "Löwe 老虎 Léopar虎d虎aaab虎";
    let l30 = label_from_str(s30);
    let l32 = label_from_str(s32);
    let l33 = label_from_str(s33);
    let l34 = label_from_str(s34);
    println!("Label l30: {:?}", l30);
    println!("Label l32: {:?}", l32);
    println!("Label l33: {:?}", l33);
    println!("Label l34: {:?}", l34);
    // now the assertions:
    // - l30 must have the last 2 as byte 32
    // - l32 must not have any byte 32 at the end
    // - l33 must have the last 2 as byte 32 because the trailing '虎' is three bytes
    // - l34 must have hte last 1 as byte 32
    assert_ne!(l30[29], 32);
    assert_eq!(l30[30], 32);
    assert_eq!(l30[31], 32);
    assert_ne!(l32[31], 32);
    assert_ne!(l33[29], 32);
    assert_eq!(l33[30], 32);
    assert_eq!(l33[31], 32);
    assert_ne!(l34[30], 32);
    assert_eq!(l34[31], 32);
}
#[test]
#[serial]
fn ctx_new() {
    let res = Ctx::new(pkcs11_module_name());
    assert!(
        res.is_ok(),
        "failed to create new context: {}",
        res.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_initialize() {
    let mut ctx = Ctx::new(pkcs11_module_name()).unwrap();
    let res = unsafe { ctx.initialize(None) };
    assert!(
        res.is_ok(),
        "failed to initialize context: {}",
        res.unwrap_err()
    );
    assert!(ctx.is_initialized(), "internal state is not initialized");
}

#[test]
#[serial]
fn ctx_new_and_initialize() {
    let res = unsafe { Ctx::new_and_initialize(pkcs11_module_name()) };
    assert!(
        res.is_ok(),
        "failed to create or initialize new context: {}",
        res.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_finalize() {
    let mut ctx = unsafe { Ctx::new_and_initialize(pkcs11_module_name()).unwrap() };
    let res = ctx.finalize();
    assert!(
        res.is_ok(),
        "failed to finalize context: {}",
        res.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_get_info() {
    let ctx = unsafe { Ctx::new_and_initialize(pkcs11_module_name()).unwrap() };
    let res = ctx.get_info();
    assert!(
        res.is_ok(),
        "failed to call C_GetInfo: {}",
        res.unwrap_err()
    );
    let info = res.unwrap();
    println!("{:?}", info);

    assert_eq!("SoftHSM", String::from(info.manufacturerID));
    assert_eq!(
        "Implementation of PKCS11",
        String::from(info.libraryDescription)
    );
}

#[test]
#[serial]
fn ctx_get_function_list() {
    let ctx = unsafe { Ctx::new_and_initialize(pkcs11_module_name()).unwrap() };
    let res = ctx.get_function_list();
    assert!(
        res.is_ok(),
        "failed to call C_GetFunctionList: {}",
        res.unwrap_err()
    );
    let list = res.unwrap();
    println!("{:?}", list);
}

#[test]
#[serial]
fn ctx_get_slot_list() {
    let ctx = unsafe { Ctx::new_and_initialize(pkcs11_module_name()).unwrap() };
    let res = ctx.get_slot_list(false);
    assert!(
        res.is_ok(),
        "failed to call C_GetSlotList: {}",
        res.unwrap_err()
    );
    let slots = res.unwrap();
    println!("Slots: {:?}", slots);
}

#[test]
#[serial]
fn ctx_get_slot_infos() {
    let ctx = unsafe { Ctx::new_and_initialize(pkcs11_module_name()).unwrap() };
    let slots = ctx.get_slot_list(false).unwrap();
    for slot in slots[..1].iter() {
        let slot = *slot;
        let res = ctx.get_slot_info(slot);
        assert!(
            res.is_ok(),
            "failed to call C_GetSlotInfo({}): {}",
            slot,
            res.unwrap_err()
        );
        let info = res.unwrap();
        println!("Slot {} {:?}", slot, info);
        assert_eq!("SoftHSM project", String::from(info.manufacturerID));
        assert_eq!(
            format!("SoftHSM slot ID {:#x}", slot),
            String::from(info.slotDescription)
        );
    }
}

#[test]
#[serial]
fn ctx_get_token_infos() {
    let ctx = unsafe { Ctx::new_and_initialize(pkcs11_module_name()).unwrap() };
    let slots = ctx.get_slot_list(false).unwrap();
    for slot in slots[..1].iter() {
        let slot = *slot;
        let res = ctx.get_token_info(slot);
        assert!(
            res.is_ok(),
            "failed to call C_GetTokenInfo({}): {}",
            slot,
            res.unwrap_err()
        );
        let info = res.unwrap();
        println!("Slot {} {:?}", slot, info);
        assert_eq!("rust-unit-test", String::from(info.label));
        assert_eq!("SoftHSM project", String::from(info.manufacturerID));
        assert_eq!("SoftHSM v2", String::from(info.model));
    }
}

#[test]
#[serial]
fn ctx_get_mechanism_lists() {
    let ctx = unsafe { Ctx::new_and_initialize(pkcs11_module_name()).unwrap() };
    let slots = ctx.get_slot_list(false).unwrap();
    for slot in slots[..1].iter() {
        let slot = *slot;
        let res = ctx.get_mechanism_list(slot);
        assert!(
            res.is_ok(),
            "failed to call C_GetMechanismList({}): {}",
            slot,
            res.unwrap_err()
        );
        let mechs = res.unwrap();
        println!("Slot {} Mechanisms: {:?}", slot, mechs);
    }
}

#[test]
#[serial]
fn ctx_get_mechanism_infos() {
    let ctx = unsafe { Ctx::new_and_initialize(pkcs11_module_name()).unwrap() };
    let slots = ctx.get_slot_list(false).unwrap();
    for slot in slots[..1].iter() {
        let slot = *slot;
        let mechanisms = ctx.get_mechanism_list(slot).unwrap();
        for mechanism in mechanisms {
            let res = ctx.get_mechanism_info(slot, mechanism);
            assert!(
                res.is_ok(),
                "failed to call C_GetMechanismInfo({}, {}): {}",
                slot,
                mechanism,
                res.unwrap_err()
            );
            let info = res.unwrap();
            println!("Slot {} Mechanism {}: {:?}", slot, mechanism, info);
        }
    }
}

#[test]
#[serial]
fn ctx_init_token() {
    let ctx = unsafe { Ctx::new_and_initialize(pkcs11_module_name()).unwrap() };
    let slots = ctx.get_slot_list(false).unwrap();
    let pin = Some("1234");
    const LABEL: &str = "rust-unit-test";
    for slot in slots[..1].iter() {
        let slot = *slot;
        let res = ctx.init_token(slot, pin, LABEL);
        assert!(
            res.is_ok(),
            "failed to call C_InitToken({}, {}, {}): {}",
            slot,
            pin.unwrap(),
            LABEL,
            res.unwrap_err()
        );
        println!(
            "Slot {} C_InitToken successful, PIN: {}",
            slot,
            pin.unwrap()
        );
    }
}

#[test]
#[serial]
fn ctx_init_pin() {
    let ctx = unsafe { Ctx::new_and_initialize(pkcs11_module_name()).unwrap() };
    let slots = ctx.get_slot_list(false).unwrap();
    let pin = Some("1234");
    const LABEL: &str = "rust-unit-test";
    for slot in slots[..1].iter() {
        let slot = *slot;
        ctx.init_token(slot, pin, LABEL).unwrap();
        let sh = ctx
            .open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)
            .unwrap();
        ctx.login(sh, CKU_SO, pin).unwrap();
        let res = ctx.init_pin(sh, pin);
        assert!(
            res.is_ok(),
            "failed to call C_InitPIN({}, {}): {}",
            sh,
            pin.unwrap(),
            res.unwrap_err()
        );
        println!("InitPIN successful");
    }
}

#[test]
#[serial]
fn ctx_set_pin() {
    let ctx = unsafe { Ctx::new_and_initialize(pkcs11_module_name()).unwrap() };
    let slots = ctx.get_slot_list(false).unwrap();
    let pin = Some("1234");
    let new_pin = Some("1234");
    const LABEL: &str = "rust-unit-test";
    for slot in slots[..1].iter() {
        let slot = *slot;
        ctx.init_token(slot, pin, LABEL).unwrap();
        let sh = ctx
            .open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)
            .unwrap();
        ctx.login(sh, CKU_SO, pin).unwrap();
        let res = ctx.set_pin(sh, pin, new_pin);
        assert!(
            res.is_ok(),
            "failed to call C_SetPIN({}, {}, {}): {}",
            sh,
            pin.unwrap(),
            new_pin.unwrap(),
            res.unwrap_err()
        );
        println!("SetPIN successful");
    }
}

#[test]
#[serial]
fn ctx_open_session() {
    let ctx = unsafe { Ctx::new_and_initialize(pkcs11_module_name()).unwrap() };
    let slots = ctx.get_slot_list(false).unwrap();
    let pin = Some("1234");
    const LABEL: &str = "rust-unit-test";
    for slot in slots[..1].iter() {
        let slot = *slot;
        ctx.init_token(slot, pin, LABEL).unwrap();
        let res = ctx.open_session(slot, CKF_SERIAL_SESSION, None, None);
        assert!(
            res.is_ok(),
            "failed to call C_OpenSession({}, CKF_SERIAL_SESSION, None, None): {}",
            slot,
            res.unwrap_err()
        );
        let sh = res.unwrap();
        println!("Opened Session on Slot {}: CK_SESSION_HANDLE {}", slot, sh);
    }
}

#[test]
#[serial]
fn ctx_close_session() {
    let ctx = unsafe { Ctx::new_and_initialize(pkcs11_module_name()).unwrap() };
    let slots = ctx.get_slot_list(false).unwrap();
    let pin = Some("1234");
    const LABEL: &str = "rust-unit-test";
    for slot in slots[..1].iter() {
        let slot = *slot;
        ctx.init_token(slot, pin, LABEL).unwrap();
        let sh = ctx
            .open_session(slot, CKF_SERIAL_SESSION, None, None)
            .unwrap();
        let res = ctx.close_session(sh);
        assert!(
            res.is_ok(),
            "failed to call C_CloseSession({}): {}",
            sh,
            res.unwrap_err()
        );
        println!("Closed Session with CK_SESSION_HANDLE {}", sh);
    }
}

#[test]
#[serial]
fn ctx_close_all_sessions() {
    let ctx = unsafe { Ctx::new_and_initialize(pkcs11_module_name()).unwrap() };
    let slots = ctx.get_slot_list(false).unwrap();
    let pin = Some("1234");
    const LABEL: &str = "rust-unit-test";
    for slot in slots[..1].iter() {
        let slot = *slot;
        ctx.init_token(slot, pin, LABEL).unwrap();
        ctx.open_session(slot, CKF_SERIAL_SESSION, None, None)
            .unwrap();
        let res = ctx.close_all_sessions(slot);
        assert!(
            res.is_ok(),
            "failed to call C_CloseAllSessions({}): {}",
            slot,
            res.unwrap_err()
        );
        println!("Closed All Sessions on Slot {}", slot);
    }
}

#[test]
#[serial]
fn ctx_get_session_info() {
    let ctx = unsafe { Ctx::new_and_initialize(pkcs11_module_name()).unwrap() };
    let slots = ctx.get_slot_list(false).unwrap();
    let pin = Some("1234");
    const LABEL: &str = "rust-unit-test";
    for slot in slots[..1].iter() {
        let slot = *slot;
        ctx.init_token(slot, pin, LABEL).unwrap();
        let sh = ctx
            .open_session(slot, CKF_SERIAL_SESSION, None, None)
            .unwrap();
        let res = ctx.get_session_info(sh);
        assert!(
            res.is_ok(),
            "failed to call C_GetSessionInfo({}): {}",
            sh,
            res.unwrap_err()
        );
        let info = res.unwrap();
        println!("{:?}", info);
    }
}

#[test]
#[serial]
fn ctx_login() {
    let ctx = unsafe { Ctx::new_and_initialize(pkcs11_module_name()).unwrap() };
    let slots = ctx.get_slot_list(false).unwrap();
    let pin = Some("1234");
    const LABEL: &str = "rust-unit-test";
    for slot in slots[..1].iter() {
        let slot = *slot;
        ctx.init_token(slot, pin, LABEL).unwrap();
        let sh = ctx
            .open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)
            .unwrap();
        let res = ctx.login(sh, CKU_SO, pin);
        assert!(
            res.is_ok(),
            "failed to call C_Login({}, CKU_SO, {}): {}",
            sh,
            pin.unwrap(),
            res.unwrap_err()
        );
        println!("Login successful");
    }
}

#[test]
#[serial]
fn ctx_logout() {
    let ctx = unsafe { Ctx::new_and_initialize(pkcs11_module_name()).unwrap() };
    let slots = ctx.get_slot_list(false).unwrap();
    let pin = Some("1234");
    const LABEL: &str = "rust-unit-test";
    for slot in slots[..1].iter() {
        let slot = *slot;
        ctx.init_token(slot, pin, LABEL).unwrap();
        let sh = ctx
            .open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)
            .unwrap();
        ctx.login(sh, CKU_SO, pin).unwrap();
        let res = ctx.logout(sh);
        assert!(
            res.is_ok(),
            "failed to call C_Logout({}): {}",
            sh,
            res.unwrap_err()
        );
        println!("Logout successful");
    }
}

#[test]
fn attr_bool() {
    let b: CK_BBOOL = CK_FALSE;
    let attr = CK_ATTRIBUTE::new(CKA_OTP_USER_IDENTIFIER).with_bool(&b);
    println!("{:?}", attr);
    let ret: bool = attr.get_bool().unwrap();
    println!("{}", ret);
    assert_eq!(false, ret, "attr.get_bool() should have been false");

    let b: CK_BBOOL = CK_TRUE;
    let attr = CK_ATTRIBUTE::new(CKA_OTP_USER_IDENTIFIER).with_bool(&b);
    println!("{:?}", attr);
    let ret: bool = attr.get_bool().unwrap();
    println!("{}", ret);
    assert_eq!(true, ret, "attr.get_bool() should have been true");
}

#[test]
fn attr_ck_ulong() {
    let val: CK_ULONG = 42;
    let attr = CK_ATTRIBUTE::new(CKA_RESOLUTION).with_ck_ulong(&val);
    println!("{:?}", attr);
    let ret: CK_ULONG = attr.get_ck_ulong().unwrap();
    println!("{}", ret);
    assert_eq!(val, ret, "attr.get_ck_ulong() shouls have been {}", val);
}

#[test]
fn attr_ck_long() {
    let val: CK_LONG = -42;
    let attr = CK_ATTRIBUTE::new(CKA_RESOLUTION).with_ck_long(&val);
    println!("{:?}", attr);
    let ret: CK_LONG = attr.get_ck_long().unwrap();
    println!("{}", ret);
    assert_eq!(val, ret, "attr.get_ck_long() shouls have been {}", val);
}

#[test]
fn attr_bytes() {
    let val = vec![0, 1, 2, 3, 3, 4, 5];
    let attr = CK_ATTRIBUTE::new(CKA_VALUE).with_bytes(val.as_slice());
    println!("{:?}", attr);
    let ret: Vec<CK_BYTE> = attr.get_bytes().unwrap();
    println!("{:?}", ret);
    assert_eq!(
        val,
        ret.as_slice(),
        "attr.get_bytes() shouls have been {:?}",
        val
    );
}

#[test]
fn attr_string() {
    let val = String::from("Löwe 老虎");
    let attr = CK_ATTRIBUTE::new(CKA_LABEL).with_string(&val);
    println!("{:?}", attr);
    let ret = attr.get_string().unwrap();
    println!("{:?}", ret);
    assert_eq!(val, ret, "attr.get_string() shouls have been {}", val);
}

#[test]
fn attr_date() {
    let val: CK_DATE = Default::default();
    let attr = CK_ATTRIBUTE::new(CKA_LABEL).with_date(&val);
    println!("{:?}", attr);
    let ret = attr.get_date().unwrap();
    println!("{:?}", ret);
    assert_eq!(
        val.day, ret.day,
        "attr.get_date() should have been {:?}",
        val
    );
    assert_eq!(
        val.month, ret.month,
        "attr.get_date() should have been {:?}",
        val
    );
    assert_eq!(
        val.year, ret.year,
        "attr.get_date() should have been {:?}",
        val
    );
}

#[test]
fn attr_biginteger() {
    let num_str = "123456789012345678901234567890123456789012345678901234567890123456789012345678";
    let val = BigUint::from_str_radix(num_str, 10).unwrap();
    let slice = val.to_bytes_le();
    let attr = CK_ATTRIBUTE::new(CKA_LABEL).with_biginteger(&slice);
    println!("{:?}", attr);
    let ret = attr.get_biginteger().unwrap();
    println!("{:?}", ret);
    assert_eq!(ret, val, "attr.get_biginteger() should have been {:?}", val);
    assert_eq!(
        ret.to_str_radix(10),
        num_str,
        "attr.get_biginteger() should have been {:?}",
        num_str
    );
}

/// This will create and initialize a context, set a SO and USER PIN, and login as the USER.
/// This is the starting point for all tests that are acting on the token.
/// If you look at the tests here in a "serial" manner, if all the tests are working up until
/// here, this will always succeed.
fn fixture_token() -> Result<(Ctx, CK_SESSION_HANDLE), Error> {
    let ctx = unsafe { Ctx::new_and_initialize(pkcs11_module_name()).unwrap() };
    let slots = ctx.get_slot_list(false).unwrap();
    let pin = Some("1234");
    const LABEL: &str = "rust-unit-test";
    let slot = *slots.first().ok_or(Error::Module("no slot available"))?;
    ctx.init_token(slot, pin, LABEL)?;
    let sh = ctx.open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)?;
    ctx.login(sh, CKU_SO, pin)?;
    ctx.init_pin(sh, pin)?;
    ctx.logout(sh)?;
    ctx.login(sh, CKU_USER, pin)?;
    Ok((ctx, sh))
}

#[test]
#[serial]
fn ctx_create_object() {
    /*
    CKA_CLASS       ck_type  object_class:CKO_DATA
    CKA_TOKEN       bool      true
    CKA_PRIVATE     bool      true
    CKA_MODIFIABLE  bool      true
    CKA_COPYABLE    bool      true
    CKA_LABEL       string    e4-example
    CKA_VALUE       bytes     SGVsbG8gV29ybGQh
    */
    let (ctx, sh) = fixture_token().unwrap();

    let class = CKO_DATA;
    let token: CK_BBOOL = CK_TRUE;
    let private: CK_BBOOL = CK_TRUE;
    let modifiable: CK_BBOOL = CK_TRUE;
    let copyable: CK_BBOOL = CK_TRUE;
    let label = String::from("rust-unit-test");
    let value = b"Hello World!";

    let template = vec![
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&class),
        CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&token),
        CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&private),
        CK_ATTRIBUTE::new(CKA_MODIFIABLE).with_bool(&modifiable),
        CK_ATTRIBUTE::new(CKA_COPYABLE).with_bool(&copyable),
        CK_ATTRIBUTE::new(CKA_LABEL).with_string(&label),
        CK_ATTRIBUTE::new(CKA_VALUE).with_bytes(&value[..]),
    ];
    println!("Template: {:?}", template);
    let res = ctx.create_object(sh, &template);
    assert!(
        res.is_ok(),
        "failed to call C_CreateObject({}, {:?}): {}",
        sh,
        &template,
        res.is_err()
    );
    let oh = res.unwrap();
    println!("Object Handle: {}", oh);
}

fn fixture_token_and_object() -> Result<(Ctx, CK_SESSION_HANDLE, CK_OBJECT_HANDLE), Error> {
    let (ctx, sh) = fixture_token()?;

    let class = CKO_DATA;
    let token: CK_BBOOL = CK_TRUE;
    let private: CK_BBOOL = CK_TRUE;
    let modifiable: CK_BBOOL = CK_TRUE;
    let copyable: CK_BBOOL = CK_TRUE;
    let label = String::from("rust-unit-test");
    let value = b"Hello World!";

    let template = vec![
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&class),
        CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&token),
        CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&private),
        CK_ATTRIBUTE::new(CKA_MODIFIABLE).with_bool(&modifiable),
        CK_ATTRIBUTE::new(CKA_COPYABLE).with_bool(&copyable),
        CK_ATTRIBUTE::new(CKA_LABEL).with_string(&label),
        CK_ATTRIBUTE::new(CKA_VALUE).with_bytes(&value[..]),
    ];
    let oh = ctx.create_object(sh, &template)?;
    Ok((ctx, sh, oh))
}

#[test]
#[serial]
fn ctx_copy_object() {
    let (ctx, sh, oh) = fixture_token_and_object().unwrap();

    let label2 = String::from("rust-unit-test2");
    let template2 = vec![CK_ATTRIBUTE::new(CKA_LABEL).with_string(&label2)];
    println!("Template2: {:?}", template2);

    let res = ctx.copy_object(sh, oh, &template2);
    assert!(
        res.is_ok(),
        "failed to call C_CopyObject({}, {}, {:?}): {}",
        sh,
        oh,
        &template2,
        res.unwrap_err(),
    );
    let oh2 = res.unwrap();
    println!("Object Handle2: {}", oh2);
}

#[test]
#[serial]
fn ctx_destroy_object() {
    let (ctx, sh, oh) = fixture_token_and_object().unwrap();

    let res = ctx.destroy_object(sh, oh);
    assert!(
        res.is_ok(),
        "failed to call C_DestroyObject({}, {}): {})",
        sh,
        oh,
        res.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_get_object_size() {
    let (ctx, sh, oh) = fixture_token_and_object().unwrap();

    let res = ctx.get_object_size(sh, oh);
    assert!(
        res.is_ok(),
        "failed to call C_GetObjectSize({}, {}): {}",
        sh,
        oh,
        res.unwrap_err()
    );
    let size = res.unwrap();
    println!("Object Size: {}", size);
}

#[test]
#[serial]
fn ctx_get_attribute_value() {
    {
        let (ctx, sh, oh) = fixture_token_and_object().unwrap();

        let mut template = vec![
            CK_ATTRIBUTE::new(CKA_CLASS),
            CK_ATTRIBUTE::new(CKA_PRIVATE),
            CK_ATTRIBUTE::new(CKA_LABEL),
            CK_ATTRIBUTE::new(CKA_VALUE),
        ];
        println!("Template: {:?}", template);
        {
            let res = ctx.get_attribute_value(sh, oh, &mut template);
            if !res.is_ok() {
                // Doing this not as an assert so we can both unwrap_err with the mut template and re-borrow template
                let err = res.unwrap_err();
                panic!(
                    "failed to call C_GetAttributeValue({}, {}, {:?}): {}",
                    sh, oh, &template, err
                );
            }
            let (rv, _) = res.unwrap();
            println!("CK_RV: 0x{:x}, Template: {:?}", rv, &template);
        }

        let class: CK_ULONG = 0;
        let private: CK_BBOOL = 1;
        let label: String = String::with_capacity(template[2].ulValueLen.try_into().unwrap());
        let value: Vec<CK_BYTE> = Vec::with_capacity(template[3].ulValueLen.try_into().unwrap());
        template[0].set_ck_ulong(&class);
        template[1].set_bool(&private);
        template[2].set_string(&label);
        template[3].set_bytes(&value.as_slice());

        let res = ctx.get_attribute_value(sh, oh, &mut template);
        if !res.is_ok() {
            // Doing this not as an assert so we can both unwrap_err with the mut template and re-borrow template
            let err = res.unwrap_err();
            panic!(
                "failed to call C_GetAttributeValue({}, {}, {:?}): {}",
                sh, oh, &template, err
            );
        }
        let (rv, _) = res.unwrap();
        println!("CK_RV: 0x{:x}, Retrieved Attributes: {:?}", rv, &template);

        assert_eq!(CKO_DATA, template[0].get_ck_ulong().unwrap());
        assert_eq!(true, template[1].get_bool().unwrap());
        assert_eq!(
            String::from("rust-unit-test"),
            template[2].get_string().unwrap()
        );
        assert_eq!(Vec::from("Hello World!"), template[3].get_bytes().unwrap());
    }
    println!("The end");
}

#[test]
#[serial]
fn ctx_set_attribute_value() {
    let (ctx, sh, oh) = fixture_token_and_object().unwrap();

    let value = b"Hello New World!";
    let template = vec![CK_ATTRIBUTE::new(CKA_LABEL).with_bytes(&value[..])];

    let res = ctx.set_attribute_value(sh, oh, &template);
    assert!(
        res.is_ok(),
        "failed to call C_SetAttributeValue({}, {}, {:?}): {}",
        sh,
        oh,
        &template,
        res.unwrap_err()
    );

    let str: Vec<CK_BYTE> = Vec::from("aaaaaaaaaaaaaaaa");
    let mut template2 = vec![CK_ATTRIBUTE::new(CKA_LABEL).with_bytes(&str.as_slice())];
    ctx.get_attribute_value(sh, oh, &mut template2).unwrap();
    assert_eq!(
        Vec::from("Hello New World!"),
        template2[0].get_bytes().unwrap()
    );
}

#[test]
#[serial]
fn ctx_find_objects_init() {
    let (ctx, sh, _) = fixture_token_and_object().unwrap();

    let label = String::from("rust-unit-test");
    let template = vec![CK_ATTRIBUTE::new(CKA_LABEL).with_string(&label)];

    let res = ctx.find_objects_init(sh, &template);
    assert!(
        res.is_ok(),
        "failed to call C_FindObjectsInit({}, {:?}): {}",
        sh,
        &template,
        res.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_find_objects() {
    let (ctx, sh, _) = fixture_token_and_object().unwrap();

    let label = String::from("rust-unit-test");
    let template = vec![CK_ATTRIBUTE::new(CKA_LABEL).with_string(&label)];

    ctx.find_objects_init(sh, &template).unwrap();

    let res = ctx.find_objects(sh, 10);
    assert!(
        res.is_ok(),
        "failed to call C_FindObjects({}, {}): {}",
        sh,
        10,
        res.unwrap_err()
    );
    let objs = res.unwrap();
    assert_eq!(objs.len(), 1);
}

#[test]
#[serial]
fn ctx_find_objects_final() {
    let (ctx, sh, _) = fixture_token_and_object().unwrap();

    let label = String::from("rust-unit-test");
    let template = vec![CK_ATTRIBUTE::new(CKA_LABEL).with_string(&label)];

    ctx.find_objects_init(sh, &template).unwrap();
    ctx.find_objects(sh, 10).unwrap();

    let res = ctx.find_objects_final(sh);
    assert!(
        res.is_ok(),
        "failed to call C_FindObjectsFinal({}): {}",
        sh,
        res.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_generate_key() {
    let (ctx, sh) = fixture_token().unwrap();

    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_GEN,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    // Wrapping Key Template:
    // CKA_CLASS        ck_type  object_class:CKO_SECRET_KEY
    // CKA_KEY_TYPE     ck_type  key_type:CKK_AES
    // CKA_TOKEN        bool     true
    // CKA_LABEL        string   wrap1-wrap-key
    // CKA_ENCRYPT      bool     false
    // CKA_DECRYPT      bool     false
    // CKA_VALUE_LEN    uint     32
    // CKA_PRIVATE      bool     true
    // CKA_SENSITIVE    bool     false
    // CKA_EXTRACTABLE  bool     true
    // CKA_WRAP         bool     true
    // CKA_UNWRAP       bool     true

    let class = CKO_SECRET_KEY;
    let keyType = CKK_AES;
    let valueLen = 32;
    let label = String::from("wrap1-wrap-key");
    let token: CK_BBOOL = CK_TRUE;
    let private: CK_BBOOL = CK_TRUE;
    let encrypt: CK_BBOOL = CK_FALSE;
    let decrypt: CK_BBOOL = CK_FALSE;
    let sensitive: CK_BBOOL = CK_FALSE;
    let extractable: CK_BBOOL = CK_TRUE;
    let wrap: CK_BBOOL = CK_TRUE;
    let unwrap: CK_BBOOL = CK_TRUE;

    let template = vec![
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&class),
        CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&keyType),
        CK_ATTRIBUTE::new(CKA_VALUE_LEN).with_ck_ulong(&valueLen),
        CK_ATTRIBUTE::new(CKA_LABEL).with_string(&label),
        CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&token),
        CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&private),
        CK_ATTRIBUTE::new(CKA_ENCRYPT).with_bool(&encrypt),
        CK_ATTRIBUTE::new(CKA_DECRYPT).with_bool(&decrypt),
        CK_ATTRIBUTE::new(CKA_SENSITIVE).with_bool(&sensitive),
        CK_ATTRIBUTE::new(CKA_EXTRACTABLE).with_bool(&extractable),
        CK_ATTRIBUTE::new(CKA_WRAP).with_bool(&wrap),
        CK_ATTRIBUTE::new(CKA_UNWRAP).with_bool(&unwrap),
    ];

    let res = ctx.generate_key(sh, &mechanism, &template);
    assert!(
        res.is_ok(),
        "failed to call C_Generatekey({}, {:?}, {:?}): {}",
        sh,
        mechanism,
        template,
        res.unwrap_err()
    );
    let oh = res.unwrap();
    assert_ne!(oh, CK_INVALID_HANDLE);
    println!("Generated Key Object Handle: {}", oh);
}

#[test]
#[serial]
fn ctx_generate_key_pair() {
    let (ctx, sh) = fixture_token().unwrap();

    let mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    // Private Key Template
    // CKA_CLASS         ck_type  object_class:CKO_PRIVATE_KEY
    // CKA_KEY_TYPE      ck_type  key_type:CKK_RSA
    // CKA_TOKEN         bool     true
    // CKA_SENSITIVE     bool     true
    // CKA_UNWRAP        bool     false
    // CKA_EXTRACTABLE   bool     false
    // CKA_LABEL         string   ca-hsm-priv
    // CKA_SIGN          bool     true
    // CKA_PRIVATE       bool     true

    let privClass = CKO_PRIVATE_KEY;
    let privKeyType = CKK_RSA;
    let privLabel = String::from("ca-hsm-priv");
    let privToken = CK_TRUE;
    let privPrivate = CK_TRUE;
    let privSensitive = CK_TRUE;
    let privUnwrap = CK_FALSE;
    let privExtractable = CK_FALSE;
    let privSign = CK_TRUE;

    let privTemplate = vec![
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&privClass),
        CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&privKeyType),
        CK_ATTRIBUTE::new(CKA_LABEL).with_string(&privLabel),
        CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&privToken),
        CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&privPrivate),
        CK_ATTRIBUTE::new(CKA_SENSITIVE).with_bool(&privSensitive),
        CK_ATTRIBUTE::new(CKA_UNWRAP).with_bool(&privUnwrap),
        CK_ATTRIBUTE::new(CKA_EXTRACTABLE).with_bool(&privExtractable),
        CK_ATTRIBUTE::new(CKA_SIGN).with_bool(&privSign),
    ];

    // Public Key Template
    // CKA_CLASS             ck_type       object_class:CKO_PUBLIC_KEY
    // CKA_KEY_TYPE          ck_type       key_type:CKK_RSA
    // CKA_TOKEN             bool          true
    // CKA_MODULUS_BITS      uint          4096
    // CKA_PUBLIC_EXPONENT   big_integer   65537
    // CKA_LABEL             string        ca-hsm-pub
    // CKA_WRAP              bool          false
    // CKA_VERIFY            bool          true
    // CKA_PRIVATE           bool          true

    let pubClass = CKO_PUBLIC_KEY;
    let pubKeyType = CKK_RSA;
    let pubLabel = String::from("ca-hsm-pub");
    let pubToken = CK_TRUE;
    let pubPrivate = CK_TRUE;
    let pubWrap = CK_FALSE;
    let pubVerify = CK_TRUE;
    let pubModulusBits: CK_ULONG = 4096;
    let pubPublicExponent = BigUint::from(65537u32);
    let pubPublicExponentSlice = pubPublicExponent.to_bytes_le();

    let pubTemplate = vec![
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&pubClass),
        CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&pubKeyType),
        CK_ATTRIBUTE::new(CKA_LABEL).with_string(&pubLabel),
        CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&pubToken),
        CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&pubPrivate),
        CK_ATTRIBUTE::new(CKA_WRAP).with_bool(&pubWrap),
        CK_ATTRIBUTE::new(CKA_VERIFY).with_bool(&pubVerify),
        CK_ATTRIBUTE::new(CKA_MODULUS_BITS).with_ck_ulong(&pubModulusBits),
        CK_ATTRIBUTE::new(CKA_PUBLIC_EXPONENT).with_biginteger(&pubPublicExponentSlice),
    ];

    let res = ctx.generate_key_pair(sh, &mechanism, &pubTemplate, &privTemplate);
    assert!(
        res.is_ok(),
        "failed to call C_GenerateKeyPair({}, {:?}, {:?}, {:?}): {}",
        sh,
        &mechanism,
        &pubTemplate,
        &privTemplate,
        res.unwrap_err()
    );
    let (pubOh, privOh) = res.unwrap();
    println!("Private Key Object Handle: {}", privOh);
    println!("Public Key Object Handle: {}", pubOh);
}

fn fixture_token_and_secret_keys(
) -> Result<(Ctx, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), Error> {
    let (ctx, sh) = fixture_token()?;

    let wrapOh: CK_OBJECT_HANDLE;
    let secOh: CK_OBJECT_HANDLE;
    {
        let mechanism = CK_MECHANISM {
            mechanism: CKM_AES_KEY_GEN,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };

        let class = CKO_SECRET_KEY;
        let keyType = CKK_AES;
        let valueLen = 32;
        let label = String::from("wrap1-wrap-key");
        let token: CK_BBOOL = CK_TRUE;
        let private: CK_BBOOL = CK_TRUE;
        let encrypt: CK_BBOOL = CK_FALSE;
        let decrypt: CK_BBOOL = CK_FALSE;
        let sensitive: CK_BBOOL = CK_FALSE;
        let extractable: CK_BBOOL = CK_TRUE;
        let wrap: CK_BBOOL = CK_TRUE;
        let unwrap: CK_BBOOL = CK_TRUE;

        let template = vec![
            CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&class),
            CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&keyType),
            CK_ATTRIBUTE::new(CKA_VALUE_LEN).with_ck_ulong(&valueLen),
            CK_ATTRIBUTE::new(CKA_LABEL).with_string(&label),
            CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&token),
            CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&private),
            CK_ATTRIBUTE::new(CKA_ENCRYPT).with_bool(&encrypt),
            CK_ATTRIBUTE::new(CKA_DECRYPT).with_bool(&decrypt),
            CK_ATTRIBUTE::new(CKA_SENSITIVE).with_bool(&sensitive),
            CK_ATTRIBUTE::new(CKA_EXTRACTABLE).with_bool(&extractable),
            CK_ATTRIBUTE::new(CKA_WRAP).with_bool(&wrap),
            CK_ATTRIBUTE::new(CKA_UNWRAP).with_bool(&unwrap),
        ];

        wrapOh = ctx.generate_key(sh, &mechanism, &template)?;
    }

    {
        let mechanism = CK_MECHANISM {
            mechanism: CKM_AES_KEY_GEN,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };

        // CKA_CLASS        ck_type  object_class:CKO_SECRET_KEY
        // CKA_KEY_TYPE     ck_type  key_type:CKK_AES
        // CKA_TOKEN        bool     true
        // CKA_LABEL        string   secured-key
        // CKA_ENCRYPT      bool     true
        // CKA_DECRYPT      bool     true
        // CKA_VALUE_LEN    uint     32
        // CKA_PRIVATE      bool     true
        // CKA_SENSITIVE    bool     true
        // CKA_EXTRACTABLE  bool     true
        // CKA_WRAP         bool     false
        // CKA_UNWRAP       bool     false

        let class = CKO_SECRET_KEY;
        let keyType = CKK_AES;
        let valueLen = 32;
        let label = String::from("secured-key");
        let token: CK_BBOOL = CK_TRUE;
        let private: CK_BBOOL = CK_TRUE;
        let encrypt: CK_BBOOL = CK_TRUE;
        let decrypt: CK_BBOOL = CK_TRUE;
        let sensitive: CK_BBOOL = CK_TRUE;
        let extractable: CK_BBOOL = CK_TRUE;
        let wrap: CK_BBOOL = CK_FALSE;
        let unwrap: CK_BBOOL = CK_FALSE;

        let template = vec![
            CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&class),
            CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&keyType),
            CK_ATTRIBUTE::new(CKA_VALUE_LEN).with_ck_ulong(&valueLen),
            CK_ATTRIBUTE::new(CKA_LABEL).with_string(&label),
            CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&token),
            CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&private),
            CK_ATTRIBUTE::new(CKA_ENCRYPT).with_bool(&encrypt),
            CK_ATTRIBUTE::new(CKA_DECRYPT).with_bool(&decrypt),
            CK_ATTRIBUTE::new(CKA_SENSITIVE).with_bool(&sensitive),
            CK_ATTRIBUTE::new(CKA_EXTRACTABLE).with_bool(&extractable),
            CK_ATTRIBUTE::new(CKA_WRAP).with_bool(&wrap),
            CK_ATTRIBUTE::new(CKA_UNWRAP).with_bool(&unwrap),
        ];

        secOh = ctx.generate_key(sh, &mechanism, &template)?;
    }

    Ok((ctx, sh, wrapOh, secOh))
}

fn fixture_token_and_key_pair(
) -> Result<(Ctx, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), Error> {
    let (ctx, sh) = fixture_token()?;
    let (pubOh, privOh) = fixture_key_pair(
        &ctx,
        sh,
        "rsa-pub".into(),
        "rsa-priv".into(),
        true,
        true,
        true,
    )?;
    Ok((ctx, sh, pubOh, privOh))
}

fn fixture_key_pair(
    ctx: &Ctx,
    sh: CK_SESSION_HANDLE,
    pubLabel: String,
    privLabel: String,
    signVerify: bool,
    encryptDecrypt: bool,
    recover: bool,
) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), Error> {
    let mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let privClass = CKO_PRIVATE_KEY;
    let privKeyType = CKK_RSA;
    let privLabel = privLabel;
    let privToken = CK_TRUE;
    let privPrivate = CK_TRUE;
    let privSensitive = CK_TRUE;
    let privUnwrap = CK_FALSE;
    let privExtractable = CK_FALSE;
    let privSign = if signVerify { CK_TRUE } else { CK_FALSE };
    let privSignRecover = if recover { CK_TRUE } else { CK_FALSE };
    let privDecrypt = if encryptDecrypt { CK_TRUE } else { CK_FALSE };

    let privTemplate = vec![
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&privClass),
        CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&privKeyType),
        CK_ATTRIBUTE::new(CKA_LABEL).with_string(&privLabel),
        CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&privToken),
        CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&privPrivate),
        CK_ATTRIBUTE::new(CKA_SENSITIVE).with_bool(&privSensitive),
        CK_ATTRIBUTE::new(CKA_UNWRAP).with_bool(&privUnwrap),
        CK_ATTRIBUTE::new(CKA_EXTRACTABLE).with_bool(&privExtractable),
        CK_ATTRIBUTE::new(CKA_SIGN).with_bool(&privSign),
        CK_ATTRIBUTE::new(CKA_SIGN_RECOVER).with_bool(&privSignRecover),
        CK_ATTRIBUTE::new(CKA_DECRYPT).with_bool(&privDecrypt),
    ];

    let pubClass = CKO_PUBLIC_KEY;
    let pubKeyType = CKK_RSA;
    let pubLabel = pubLabel;
    let pubToken = CK_TRUE;
    let pubPrivate = CK_TRUE;
    let pubWrap = CK_FALSE;
    let pubVerify = if signVerify { CK_TRUE } else { CK_FALSE };
    let pubVerifyRecover = if recover { CK_TRUE } else { CK_FALSE };
    let pubEncrypt = if encryptDecrypt { CK_TRUE } else { CK_FALSE };
    let pubModulusBits: CK_ULONG = 4096;
    let pubPublicExponent = BigUint::from(65537u32);
    let pubPublicExponentSlice = pubPublicExponent.to_bytes_le();

    let pubTemplate = vec![
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&pubClass),
        CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&pubKeyType),
        CK_ATTRIBUTE::new(CKA_LABEL).with_string(&pubLabel),
        CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&pubToken),
        CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&pubPrivate),
        CK_ATTRIBUTE::new(CKA_WRAP).with_bool(&pubWrap),
        CK_ATTRIBUTE::new(CKA_VERIFY).with_bool(&pubVerify),
        CK_ATTRIBUTE::new(CKA_VERIFY_RECOVER).with_bool(&pubVerifyRecover),
        CK_ATTRIBUTE::new(CKA_ENCRYPT).with_bool(&pubEncrypt),
        CK_ATTRIBUTE::new(CKA_MODULUS_BITS).with_ck_ulong(&pubModulusBits),
        CK_ATTRIBUTE::new(CKA_PUBLIC_EXPONENT).with_biginteger(&pubPublicExponentSlice),
    ];

    let (pubOh, privOh) = ctx.generate_key_pair(sh, &mechanism, &pubTemplate, &privTemplate)?;
    Ok((pubOh, privOh))
}

fn fixture_dh_key_pair(
    ctx: &Ctx,
    sh: CK_SESSION_HANDLE,
    pubLabel: String,
    privLabel: String,
) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), Error> {
    let mechanism = CK_MECHANISM {
        mechanism: CKM_DH_PKCS_KEY_PAIR_GEN,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    //[]*pkcs11.Attribute{
    //	pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
    //	pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_DH),
    //	pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
    //	pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
    //	pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
    //},
    let privClass = CKO_PRIVATE_KEY;
    let privKeyType = CKK_DH;
    let privLabel = privLabel;
    let privToken = CK_TRUE;
    let privPrivate = CK_TRUE;
    let privSensitive = CK_TRUE;
    let privExtractable = CK_FALSE;
    let privDerive = CK_TRUE;

    let privTemplate = vec![
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&privClass),
        CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&privKeyType),
        CK_ATTRIBUTE::new(CKA_LABEL).with_string(&privLabel),
        CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&privToken),
        CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&privPrivate),
        CK_ATTRIBUTE::new(CKA_SENSITIVE).with_bool(&privSensitive),
        CK_ATTRIBUTE::new(CKA_EXTRACTABLE).with_bool(&privExtractable),
        CK_ATTRIBUTE::new(CKA_DERIVE).with_bool(&privDerive),
    ];

    /*
              []*pkcs11.Attribute{
                  pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
                  pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_DH),
                  pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
                  pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
                  pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
                  pkcs11.NewAttribute(pkcs11.CKA_BASE, domainParamBase.Bytes()),
                  pkcs11.NewAttribute(pkcs11.CKA_PRIME, domainParamPrime.Bytes()),
              },
    */

    let pubClass = CKO_PUBLIC_KEY;
    let pubKeyType = CKK_DH;
    let pubLabel = pubLabel;
    let pubToken = CK_TRUE;
    let pubPrivate = CK_TRUE;
    let pubDerive = CK_TRUE;
    //  2048-bit MODP Group
    let prime: Vec<u8> = Vec::from_hex(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
  ).unwrap();
    // 1536-bit MODP Group
    //let base: Vec<u8> = Vec::from_hex(
    //  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
    //).unwrap();
    let base: Vec<u8> = Vec::from_hex("02").unwrap();

    let pubTemplate = vec![
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&pubClass),
        CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&pubKeyType),
        CK_ATTRIBUTE::new(CKA_LABEL).with_string(&pubLabel),
        CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&pubToken),
        CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&pubPrivate),
        CK_ATTRIBUTE::new(CKA_DERIVE).with_bool(&pubDerive),
        CK_ATTRIBUTE::new(CKA_BASE).with_bytes(&base.as_slice()),
        CK_ATTRIBUTE::new(CKA_PRIME).with_bytes(&prime.as_slice()),
    ];

    let (pubOh, privOh) = ctx.generate_key_pair(sh, &mechanism, &pubTemplate, &privTemplate)?;
    Ok((pubOh, privOh))
}

#[test]
#[serial]
fn ctx_sign_init() {
    let (ctx, sh, _, privOh) = fixture_token_and_key_pair().unwrap();

    let parameter = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CKM_SHA256,
        mgf: CKG_MGF1_SHA256,
        sLen: 32,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS_PSS,
        pParameter: &parameter as *const _ as CK_VOID_PTR,
        ulParameterLen: mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
    };

    let res = ctx.sign_init(sh, &mechanism, privOh);
    assert!(
        res.is_ok(),
        "failed to call C_SignInit({}, {:?}, {}) with parameter: {}",
        sh,
        &mechanism,
        privOh,
        res.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_sign() {
    let (ctx, sh, _, privOh) = fixture_token_and_key_pair().unwrap();

    let parameter = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CKM_SHA256,
        mgf: CKG_MGF1_SHA256,
        sLen: 32,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS_PSS,
        pParameter: &parameter as *const _ as CK_VOID_PTR,
        ulParameterLen: mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
    };

    let res = ctx.sign_init(sh, &mechanism, privOh);
    assert!(
        res.is_ok(),
        "failed to call C_SignInit({}, {:?}, {}) with parameter: {}",
        sh,
        &mechanism,
        privOh,
        res.unwrap_err()
    );

    let data = String::from("Lorem ipsum tralala").into_bytes();
    let signature = ctx.sign(sh, &data);
    assert!(
        signature.is_ok(),
        "failed to call C_Sign({}, {:?}): {}",
        sh,
        &data,
        signature.unwrap_err()
    );
    let signature = signature.unwrap();
    println!("Signature bytes after C_Sign: {:?}", &signature);
}

#[test]
#[serial]
fn ctx_sign_update() {
    let (ctx, sh, _, privOh) = fixture_token_and_key_pair().unwrap();

    let parameter = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CKM_SHA256,
        mgf: CKG_MGF1_SHA256,
        sLen: 32,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS_PSS,
        pParameter: &parameter as *const _ as CK_VOID_PTR,
        ulParameterLen: mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
    };

    let res = ctx.sign_init(sh, &mechanism, privOh);
    assert!(
        res.is_ok(),
        "failed to call C_SignInit({}, {:?}, {}) with parameter: {}",
        sh,
        &mechanism,
        privOh,
        res.unwrap_err()
    );

    let data = String::from("Lorem ipsum tralala").into_bytes();
    let ret = ctx.sign_update(sh, &data);
    assert!(
        ret.is_ok(),
        "failed to call C_SignUpdate({}, {:?}): {}",
        sh,
        &data,
        ret.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_sign_final() {
    let (ctx, sh, _, privOh) = fixture_token_and_key_pair().unwrap();

    let parameter = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CKM_SHA256,
        mgf: CKG_MGF1_SHA256,
        sLen: 32,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS_PSS,
        pParameter: &parameter as *const _ as CK_VOID_PTR,
        ulParameterLen: mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
    };

    let res = ctx.sign_init(sh, &mechanism, privOh);
    assert!(
        res.is_ok(),
        "failed to call C_SignInit({}, {:?}, {}) with parameter: {}",
        sh,
        &mechanism,
        privOh,
        res.unwrap_err()
    );

    let data1 = String::from("Lorem ipsum tralala").into_bytes();
    let data2 = String::from("Lorem ipsum tralala").into_bytes();
    let ret = ctx.sign_update(sh, &data1);
    assert!(
        ret.is_ok(),
        "failed to call C_SignUpdate({}, {:?}): {}",
        sh,
        &data1,
        ret.unwrap_err()
    );

    let ret = ctx.sign_update(sh, &data2);
    assert!(
        ret.is_ok(),
        "failed to call C_SignUpdate({}, {:?}): {}",
        sh,
        &data2,
        ret.unwrap_err()
    );

    let signature = ctx.sign_final(sh);
    assert!(
        signature.is_ok(),
        "failed to call C_SignFinal({}): {}",
        sh,
        signature.unwrap_err()
    );
    let signature = signature.unwrap();
    println!("Signature bytes after multi-part signing: {:?}", &signature);

    // final should complete the operation, so we should be able to init another
    let res = ctx.sign_init(sh, &mechanism, privOh);
    assert!(
        res.is_ok(),
        "failed to call C_SignInit({}, {:?}, {}) with parameter: {}",
        sh,
        &mechanism,
        privOh,
        res.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_verify_init() {
    let (ctx, sh, pubOh, _) = fixture_token_and_key_pair().unwrap();

    let parameter = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CKM_SHA256,
        mgf: CKG_MGF1_SHA256,
        sLen: 32,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS_PSS,
        pParameter: &parameter as *const _ as CK_VOID_PTR,
        ulParameterLen: mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
    };

    let res = ctx.verify_init(sh, &mechanism, pubOh);
    assert!(
        res.is_ok(),
        "failed to call C_VerifyInit({}, {:?}, {}) with parameter: {}",
        sh,
        &mechanism,
        pubOh,
        res.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_verify() {
    let (ctx, sh, pubOh, privOh) = fixture_token_and_key_pair().unwrap();

    let parameter = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CKM_SHA256,
        mgf: CKG_MGF1_SHA256,
        sLen: 32,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS_PSS,
        pParameter: &parameter as *const _ as CK_VOID_PTR,
        ulParameterLen: mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
    };

    let res = ctx.sign_init(sh, &mechanism, privOh);
    assert!(
        res.is_ok(),
        "failed to call C_SignInit({}, {:?}, {}) with parameter: {}",
        sh,
        &mechanism,
        privOh,
        res.unwrap_err()
    );

    let data = String::from("Lorem ipsum tralala").into_bytes();
    let signature = ctx.sign(sh, &data);
    assert!(
        signature.is_ok(),
        "failed to call C_Sign({}, {:?}): {}",
        sh,
        &data,
        signature.unwrap_err()
    );
    let signature = signature.unwrap();

    let res = ctx.verify_init(sh, &mechanism, pubOh);
    assert!(
        res.is_ok(),
        "failed to call C_VerifyInit({}, {:?}, {}) with parameter: {}",
        sh,
        &mechanism,
        pubOh,
        res.unwrap_err()
    );

    let res = ctx.verify(sh, &data, &signature);
    assert!(
        res.is_ok(),
        "failed to call C_Verify({}, {:?}, {:?}): {}",
        sh,
        &data,
        &signature,
        res.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_verify_update() {
    let (ctx, sh, pubOh, privOh) = fixture_token_and_key_pair().unwrap();

    let parameter = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CKM_SHA256,
        mgf: CKG_MGF1_SHA256,
        sLen: 32,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS_PSS,
        pParameter: &parameter as *const _ as CK_VOID_PTR,
        ulParameterLen: mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
    };

    let res = ctx.sign_init(sh, &mechanism, privOh);
    assert!(
        res.is_ok(),
        "failed to call C_SignInit({}, {:?}, {}) with parameter: {}",
        sh,
        &mechanism,
        privOh,
        res.unwrap_err()
    );

    let data = String::from("Lorem ipsum tralala").into_bytes();
    let signature = ctx.sign(sh, &data);
    assert!(
        signature.is_ok(),
        "failed to call C_Sign({}, {:?}): {}",
        sh,
        &data,
        signature.unwrap_err()
    );

    let res = ctx.verify_init(sh, &mechanism, pubOh);
    assert!(
        res.is_ok(),
        "failed to call C_VerifyInit({}, {:?}, {}) with parameter: {}",
        sh,
        &mechanism,
        pubOh,
        res.unwrap_err()
    );

    let res = ctx.verify_update(sh, &data);
    assert!(
        res.is_ok(),
        "failed to call C_VerifyUpdate({}, {:?}): {}",
        sh,
        &data,
        res.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_verify_final() {
    let (ctx, sh, pubOh, privOh) = fixture_token_and_key_pair().unwrap();

    let parameter = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CKM_SHA256,
        mgf: CKG_MGF1_SHA256,
        sLen: 32,
    };
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256_RSA_PKCS_PSS,
        pParameter: &parameter as *const _ as CK_VOID_PTR,
        ulParameterLen: mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
    };

    let res = ctx.sign_init(sh, &mechanism, privOh);
    assert!(
        res.is_ok(),
        "failed to call C_SignInit({}, {:?}, {}) with parameter: {}",
        sh,
        &mechanism,
        privOh,
        res.unwrap_err()
    );

    let data = String::from("Lorem ipsum tralala").into_bytes();
    let signature = ctx.sign(sh, &data);
    assert!(
        signature.is_ok(),
        "failed to call C_Sign({}, {:?}): {}",
        sh,
        &data,
        signature.unwrap_err()
    );
    let signature = signature.unwrap();

    let res = ctx.verify_init(sh, &mechanism, pubOh);
    assert!(
        res.is_ok(),
        "failed to call C_VerifyInit({}, {:?}, {}) with parameter: {}",
        sh,
        &mechanism,
        pubOh,
        res.unwrap_err()
    );

    let res = ctx.verify_update(sh, &data);
    assert!(
        res.is_ok(),
        "failed to call C_VerifyUpdate({}, {:?}): {}",
        sh,
        &data,
        res.unwrap_err()
    );

    let res = ctx.verify_final(sh, &signature);
    assert!(
        res.is_ok(),
        "failed to call C_VerifyFinal({}, {:?}): {}",
        sh,
        &signature,
        res.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_sign_recover_init() {
    let (ctx, sh, _, privOh) = fixture_token_and_key_pair().unwrap();

    let mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let res = ctx.sign_recover_init(sh, &mechanism, privOh);
    if res.is_err() {
        // SoftHSM does not support this function, so this is what we should compare against
        //assert_eq!(Error::Pkcs11(CKR_FUNCTION_NOT_SUPPORTED), res.unwrap_err());
        match res.unwrap_err() {
            Error::Pkcs11(CKR_FUNCTION_NOT_SUPPORTED) => {
                println!("as expected SoftHSM does not support this function");
            }
            _ => panic!("TODO: SoftHSM supports C_SignRecoverInit now, complete tests"),
        }
    } else {
        assert!(
            res.is_ok(),
            "failed to call C_SignRecoverInit({}, {:?}, {}) without parameter: {}",
            sh,
            &mechanism,
            privOh,
            res.unwrap_err()
        );
    }
}

#[test]
#[serial]
fn ctx_sign_recover() {
    let (ctx, sh) = fixture_token().unwrap();

    let data = String::from("Lorem ipsum tralala").into_bytes();
    let res = ctx.sign_recover(sh, &data);
    assert!(res.is_err());
    if let Error::Pkcs11(CKR_FUNCTION_NOT_SUPPORTED) = res.unwrap_err() {
        println!("SoftHSM does not support C_SignRecover at the moment");
        return;
    }
    panic!("TODO: SoftHSM supports C_SignRecover now, complete tests")
}

#[test]
#[serial]
fn ctx_verify_recover_init() {
    let (ctx, sh, pubOh, _) = fixture_token_and_key_pair().unwrap();

    let mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let res = ctx.verify_recover_init(sh, &mechanism, pubOh);
    if res.is_err() {
        // SoftHSM does not support this function, so this is what we should compare against
        //assert_eq!(Error::Pkcs11(CKR_FUNCTION_NOT_SUPPORTED), res.unwrap_err());
        match res.unwrap_err() {
            Error::Pkcs11(CKR_FUNCTION_NOT_SUPPORTED) => {
                println!("as expected SoftHSM does not support this function");
            }
            _ => panic!("TODO: SoftHSM supports C_VerifyRecoverInit now, complete tests"),
        }
    } else {
        assert!(
            res.is_ok(),
            "failed to call C_VerifyRecoverInit({}, {:?}, {}) without parameter: {}",
            sh,
            &mechanism,
            pubOh,
            res.unwrap_err()
        );
    }
}

#[test]
#[serial]
fn ctx_verify_recover() {
    let (ctx, sh) = fixture_token().unwrap();

    let data = String::from("Lorem ipsum tralala").into_bytes();
    let res = ctx.verify_recover(sh, &data);
    assert!(res.is_err());
    if let Error::Pkcs11(CKR_FUNCTION_NOT_SUPPORTED) = res.unwrap_err() {
        println!("SoftHSM does not support C_VerifyRecover at the moment");
        return;
    }
    panic!("TODO: SoftHSM supports C_VerifyRecover now, complete tests")
}

#[test]
#[serial]
fn ctx_wrap_key() {
    let (ctx, sh, wrapOh, secOh) = fixture_token_and_secret_keys().unwrap();

    // using the default IV
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP_PAD,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let res = ctx.wrap_key(sh, &mechanism, wrapOh, secOh);
    assert!(
        res.is_ok(),
        "failed to call C_WrapKey({}, {:?}, {}, {}) without parameter: {}",
        sh,
        &mechanism,
        wrapOh,
        secOh,
        res.unwrap_err()
    );
    let wrappedKey = res.unwrap();
    println!(
        "Wrapped Key Bytes (Total of {} bytes): {:?}",
        wrappedKey.len(),
        wrappedKey
    );
}

#[test]
#[serial]
fn ctx_unwrap_key() {
    let (ctx, sh, wrapOh, secOh) = fixture_token_and_secret_keys().unwrap();

    // using the default IV
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_KEY_WRAP_PAD,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let wrappedKey = ctx.wrap_key(sh, &mechanism, wrapOh, secOh).unwrap();

    let class = CKO_SECRET_KEY;
    let keyType = CKK_AES;
    let label = String::from("secured-key-unwrapped");
    let token: CK_BBOOL = CK_TRUE;
    let private: CK_BBOOL = CK_TRUE;
    let encrypt: CK_BBOOL = CK_TRUE;
    let decrypt: CK_BBOOL = CK_TRUE;
    let sensitive: CK_BBOOL = CK_TRUE;
    let extractable: CK_BBOOL = CK_TRUE;
    let wrap: CK_BBOOL = CK_FALSE;
    let unwrap: CK_BBOOL = CK_FALSE;

    let template = vec![
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&class),
        CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&keyType),
        CK_ATTRIBUTE::new(CKA_LABEL).with_string(&label),
        CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&token),
        CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&private),
        CK_ATTRIBUTE::new(CKA_ENCRYPT).with_bool(&encrypt),
        CK_ATTRIBUTE::new(CKA_DECRYPT).with_bool(&decrypt),
        CK_ATTRIBUTE::new(CKA_SENSITIVE).with_bool(&sensitive),
        CK_ATTRIBUTE::new(CKA_EXTRACTABLE).with_bool(&extractable),
        CK_ATTRIBUTE::new(CKA_WRAP).with_bool(&wrap),
        CK_ATTRIBUTE::new(CKA_UNWRAP).with_bool(&unwrap),
    ];

    let res = ctx.unwrap_key(sh, &mechanism, wrapOh, &wrappedKey, &template);
    assert!(
        res.is_ok(),
        "failed to call C_UnwrapKey({}, {:?}, {}, {:?}, {:?}): {}",
        sh,
        &mechanism,
        wrapOh,
        &wrappedKey,
        &template,
        res.unwrap_err()
    );
    let oh = res.unwrap();
    println!("New unwrapped key Object Handle: {}", oh);
}

#[test]
#[serial]
fn ctx_encrypt_init() {
    let (ctx, sh, _, secOh) = fixture_token_and_secret_keys().unwrap();

    // using AES ECB just because it is the simplest to test
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let res = ctx.encrypt_init(sh, &mechanism, secOh);
    assert!(
        res.is_ok(),
        "failed to call C_EncryptInit({}, {:?}, {}) without parameter: {}",
        sh,
        &mechanism,
        secOh,
        res.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_encrypt() {
    let (ctx, sh, _, secOh) = fixture_token_and_secret_keys().unwrap();

    // using AES ECB just because it is the simplest to test
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let res = ctx.encrypt_init(sh, &mechanism, secOh);
    assert!(
        res.is_ok(),
        "failed to call C_EncryptInit({}, {:?}, {}) without parameter: {}",
        sh,
        &mechanism,
        secOh,
        res.unwrap_err()
    );

    // plaintext is padded to one block of data: 16 bytes
    let plaintext = String::from("encrypt me      ").into_bytes();
    let res = ctx.encrypt(sh, &plaintext);
    assert!(
        res.is_ok(),
        "failed to call C_Encrypt({}, {:?}): {}",
        sh,
        &plaintext,
        res.unwrap_err()
    );
    let res = res.unwrap();
    println!("Ciphertext after single call to C_Encrypt: {:?}", res);
}

#[test]
#[serial]
fn ctx_encrypt_update() {
    let (ctx, sh, _, secOh) = fixture_token_and_secret_keys().unwrap();

    // using AES ECB just because it is the simplest to test
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let res = ctx.encrypt_init(sh, &mechanism, secOh);
    assert!(
        res.is_ok(),
        "failed to call C_EncryptInit({}, {:?}, {}) without parameter: {}",
        sh,
        &mechanism,
        secOh,
        res.unwrap_err()
    );

    // plaintext is padded to one block of data: 16 bytes
    let plaintext = String::from("encrypt me      ").into_bytes();
    let ciphertext = ctx.encrypt_update(sh, &plaintext);
    assert!(
        ciphertext.is_ok(),
        "failed to call C_EncryptUpdate({}, {:?}): {}",
        sh,
        &plaintext,
        ciphertext.unwrap_err()
    );
    let ciphertext = ciphertext.unwrap();
    println!(
        "Ciphertext after first call to C_EncryptUpdate: {:?}",
        ciphertext
    );
}

#[test]
#[serial]
fn ctx_encrypt_final() {
    let (ctx, sh, _, secOh) = fixture_token_and_secret_keys().unwrap();

    // using AES ECB just because it is the simplest to test
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let res = ctx.encrypt_init(sh, &mechanism, secOh);
    assert!(
        res.is_ok(),
        "failed to call C_EncryptInit({}, {:?}, {}) without parameter: {}",
        sh,
        &mechanism,
        secOh,
        res.unwrap_err()
    );

    // plaintext is padded to one block of data: 16 bytes
    let plaintext1 = String::from("encrypt me 1    ").into_bytes();
    let plaintext2 = String::from("encrypt me 2    ").into_bytes();

    let ciphertext1 = ctx.encrypt_update(sh, &plaintext1);
    assert!(
        ciphertext1.is_ok(),
        "failed to call C_EncryptUpdate({}, {:?}): {}",
        sh,
        &plaintext1,
        ciphertext1.unwrap_err()
    );
    let ciphertext1 = ciphertext1.unwrap();
    println!(
        "Ciphertext after first call to C_EncryptUpdate: {:?}",
        ciphertext1
    );

    let ciphertext2 = ctx.encrypt_update(sh, &plaintext2);
    assert!(
        ciphertext2.is_ok(),
        "failed to call C_EncryptUpdate({}, {:?}): {}",
        sh,
        &plaintext2,
        ciphertext2.unwrap_err()
    );
    let ciphertext2 = ciphertext2.unwrap();
    println!(
        "Ciphertext after second call to C_EncryptUpdate: {:?}",
        ciphertext2
    );

    let ciphertext3 = ctx.encrypt_final(sh);
    assert!(
        ciphertext3.is_ok(),
        "failed to call C_EncryptFinal({}): {}",
        sh,
        ciphertext3.unwrap_err()
    );
    let ciphertext3 = ciphertext3.unwrap();
    println!("Ciphertext after call to C_EncryptFinal: {:?}", ciphertext3);
}

#[test]
#[serial]
fn ctx_decrypt_init() {
    let (ctx, sh, _, secOh) = fixture_token_and_secret_keys().unwrap();

    // using AES ECB just because it is the simplest to test
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let res = ctx.decrypt_init(sh, &mechanism, secOh);
    assert!(
        res.is_ok(),
        "failed to call C_DecryptInit({}, {:?}, {}) without parameter: {}",
        sh,
        &mechanism,
        secOh,
        res.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_decrypt() {
    let (ctx, sh, _, secOh) = fixture_token_and_secret_keys().unwrap();

    // using AES ECB just because it is the simplest to test
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    // 1. encrypt some plaintext
    // plaintext is padded to one block of data: 16 bytes
    let plaintext = String::from("encrypt me      ").into_bytes();
    println!("Plaintext: {:?}", &plaintext);

    let res = ctx.encrypt_init(sh, &mechanism, secOh);
    assert!(
        res.is_ok(),
        "failed to call C_EncryptInit({}, {:?}, {}) without parameter: {}",
        sh,
        &mechanism,
        secOh,
        res.unwrap_err()
    );

    let ciphertext = ctx.encrypt(sh, &plaintext);
    assert!(
        ciphertext.is_ok(),
        "failed to call C_Encrypt({}, {:?}): {}",
        sh,
        &plaintext,
        ciphertext.unwrap_err()
    );
    let ciphertext = ciphertext.unwrap();
    println!(
        "Ciphertext after single call to C_Encrypt: {:?}",
        ciphertext
    );

    // 2. decrypt ciphertext
    let res = ctx.decrypt_init(sh, &mechanism, secOh);
    assert!(
        res.is_ok(),
        "failed to call C_DecryptInit({}, {:?}, {}) without parameter: {}",
        sh,
        &mechanism,
        secOh,
        res.unwrap_err()
    );

    let decrypted_ciphertext = ctx.decrypt(sh, &ciphertext);
    assert!(
        decrypted_ciphertext.is_ok(),
        "failed to call C_Decrypt({}, {:?}): {}",
        sh,
        &ciphertext,
        decrypted_ciphertext.unwrap_err()
    );
    let decrypted_ciphertext = decrypted_ciphertext.unwrap();
    println!(
        "Decrypted ciphertext after call to C_Decrypt: {:?}",
        &decrypted_ciphertext
    );

    // 3. match decrypted ciphertext against plaintext
    assert_eq!(plaintext, decrypted_ciphertext);
}

#[test]
#[serial]
fn ctx_decrypt_update() {
    let (ctx, sh, _, secOh) = fixture_token_and_secret_keys().unwrap();

    // using AES ECB just because it is the simplest to test
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    // 1. encrypt some plaintext
    // plaintext is padded to one block of data: 16 bytes
    let plaintext = String::from("encrypt me      ").into_bytes();
    println!("Plaintext: {:?}", &plaintext);

    let res = ctx.encrypt_init(sh, &mechanism, secOh);
    assert!(
        res.is_ok(),
        "failed to call C_EncryptInit({}, {:?}, {}) without parameter: {}",
        sh,
        &mechanism,
        secOh,
        res.unwrap_err()
    );

    let ciphertext = ctx.encrypt(sh, &plaintext);
    assert!(
        ciphertext.is_ok(),
        "failed to call C_Encrypt({}, {:?}): {}",
        sh,
        &plaintext,
        ciphertext.unwrap_err()
    );
    let ciphertext = ciphertext.unwrap();
    println!(
        "Ciphertext after single call to C_Encrypt: {:?}",
        ciphertext
    );

    // 2. start to decrypt ciphertext
    let res = ctx.decrypt_init(sh, &mechanism, secOh);
    assert!(
        res.is_ok(),
        "failed to call C_DecryptInit({}, {:?}, {}) without parameter: {}",
        sh,
        &mechanism,
        secOh,
        res.unwrap_err()
    );

    let decrypted_ciphertext = ctx.decrypt_update(sh, &ciphertext);
    assert!(
        decrypted_ciphertext.is_ok(),
        "failed to call C_DecryptUpdate({}, {:?}): {}",
        sh,
        &ciphertext,
        decrypted_ciphertext.unwrap_err()
    );
    let decrypted_ciphertext = decrypted_ciphertext.unwrap();
    println!(
        "Decrypted ciphertext after call to C_DecryptUpdate: {:?}",
        &decrypted_ciphertext
    );
}

#[test]
#[serial]
fn ctx_decrypt_final() {
    let (ctx, sh, _, secOh) = fixture_token_and_secret_keys().unwrap();

    // using AES ECB just because it is the simplest to test
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    // 1. encrypt some plaintext
    // plaintext is padded to one block of data: 16 bytes
    let plaintext1 = String::from("encrypt me 1    ").into_bytes();
    let plaintext2 = String::from("encrypt me 2    ").into_bytes();
    println!("Plaintext: {:?}", &plaintext1);

    let res = ctx.encrypt_init(sh, &mechanism, secOh);
    assert!(
        res.is_ok(),
        "failed to call C_EncryptInit({}, {:?}, {}) without parameter: {}",
        sh,
        &mechanism,
        secOh,
        res.unwrap_err()
    );

    let ciphertext1 = ctx.encrypt_update(sh, &plaintext1);
    assert!(
        ciphertext1.is_ok(),
        "failed to call C_EncryptUpdate({}, {:?}): {}",
        sh,
        &plaintext1,
        ciphertext1.unwrap_err()
    );
    let ciphertext1 = ciphertext1.unwrap();
    println!(
        "Ciphertext after first call to C_EncryptUpdate: {:?}",
        ciphertext1
    );

    let ciphertext2 = ctx.encrypt_update(sh, &plaintext2);
    assert!(
        ciphertext2.is_ok(),
        "failed to call C_EncryptUpdate({}, {:?}): {}",
        sh,
        &plaintext2,
        ciphertext2.unwrap_err()
    );
    let ciphertext2 = ciphertext2.unwrap();
    println!(
        "Ciphertext after second call to C_EncryptUpdate: {:?}",
        ciphertext2
    );

    let res = ctx.encrypt_final(sh);
    assert!(
        res.is_ok(),
        "failed to call C_EncryptFinal({}): {}",
        sh,
        res.unwrap_err()
    );
    let res = res.unwrap();
    assert!(
        res.is_empty(),
        "call to C_EncryptFinal revealed ciphertext {:?} but selected cipher should not have returned any more ciphertext",
        &res
    );
    println!("Encryption operations finished");

    // 2. start to decrypt ciphertext
    let res = ctx.decrypt_init(sh, &mechanism, secOh);
    assert!(
        res.is_ok(),
        "failed to call C_DecryptInit({}, {:?}, {}) without parameter: {}",
        sh,
        &mechanism,
        secOh,
        res.unwrap_err()
    );

    let decrypted_ciphertext1 = ctx.decrypt_update(sh, &ciphertext1);
    assert!(
        decrypted_ciphertext1.is_ok(),
        "failed to call C_Decrypt({}, {:?}): {}",
        sh,
        &ciphertext1,
        decrypted_ciphertext1.unwrap_err()
    );
    let decrypted_ciphertext1 = decrypted_ciphertext1.unwrap();
    println!(
        "Decrypted ciphertext after first call to C_DecryptUpdate: {:?}",
        &decrypted_ciphertext1
    );

    let decrypted_ciphertext2 = ctx.decrypt_update(sh, &ciphertext2);
    assert!(
        decrypted_ciphertext2.is_ok(),
        "failed to call C_Decrypt({}, {:?}): {}",
        sh,
        &ciphertext2,
        decrypted_ciphertext2.unwrap_err()
    );
    let decrypted_ciphertext2 = decrypted_ciphertext2.unwrap();
    println!(
        "Decrypted ciphertext after second call to C_DecryptUpdate: {:?}",
        &decrypted_ciphertext2
    );

    let res = ctx.decrypt_final(sh);
    assert!(
        res.is_ok(),
        "failed to call C_DecryptFinal({}): {}",
        sh,
        res.unwrap_err()
    );
    let res = res.unwrap();
    assert!(
        res.is_empty(),
        "call to C_DecryptFinal revealed plaintext {:?} but selected cipher should not have returned any more plaintext",
        &res
    );

    // 3. match decrypted ciphertexts against plaintexts
    assert_eq!(plaintext1, decrypted_ciphertext1);
    assert_eq!(plaintext2, decrypted_ciphertext2);

    // 4. ensure we can start another operation without getting blasted by CKR_OPERATION_ACTIVE
    let res = ctx.decrypt_init(sh, &mechanism, secOh);
    assert!(
        res.is_ok(),
        "failed to call C_DecryptInit({}, {:?}, {}) without parameter: {}",
        sh,
        &mechanism,
        secOh,
        res.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_digest_init() {
    let (ctx, sh) = fixture_token().unwrap();

    // using a simple SHA256 for the test
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let res = ctx.digest_init(sh, &mechanism);
    assert!(
        res.is_ok(),
        "failed to call C_DigestInit({}, {:?}) without parameter: {}",
        sh,
        &mechanism,
        res.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_digest() {
    let (ctx, sh) = fixture_token().unwrap();

    // using a simple SHA256 for the test
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let res = ctx.digest_init(sh, &mechanism);
    assert!(
        res.is_ok(),
        "failed to call C_DigestInit({}, {:?}) without parameter: {}",
        sh,
        &mechanism,
        res.unwrap_err()
    );

    let data = String::from("Lorem ipsum tralala").into_bytes();
    let digest = ctx.digest(sh, &data);
    assert!(
        digest.is_ok(),
        "failed to call C_Digest({}, {:?}): {}",
        sh,
        &data,
        digest.unwrap_err()
    );
    let digest = digest.unwrap();

    // tools like shasum are always printing lower-cased hex strings
    // so let's create one of these
    let hexString = digest
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    println!("Calculated SHA-256 Digest is: {}", hexString);

    // now let's compare! created with:
    // echo -n "Lorem ipsum tralala" | shasum -a 256 -p | awk '{ print $1 }'
    // c4b0c693eb7c30dffc5b8c037342850b95746687a636dc95ecd9d75129277002
    assert_eq!(
        hexString,
        "c4b0c693eb7c30dffc5b8c037342850b95746687a636dc95ecd9d75129277002"
    );
}

#[test]
#[serial]
fn ctx_digest_key() {
    let (ctx, sh, _, secOh) = fixture_token_and_secret_keys().unwrap();

    // using a simple SHA256 for the test
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let res = ctx.digest_init(sh, &mechanism);
    assert!(
        res.is_ok(),
        "failed to call C_DigestInit({}, {:?}) without parameter: {}",
        sh,
        &mechanism,
        res.unwrap_err()
    );

    let ret = ctx.digest_key(sh, secOh);
    assert!(
        ret.is_ok(),
        "failed to call C_DigestKey({}, {}): {}",
        sh,
        secOh,
        ret.unwrap_err()
    );

    let digest = ctx.digest_final(sh);
    assert!(
        digest.is_ok(),
        "failed to call C_DigestFinal({}): {}",
        sh,
        digest.unwrap_err()
    );
    let digest = digest.unwrap();

    // tools like shasum are always printing lower-cased hex strings
    // so let's create one of these
    let hexString = digest
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    println!(
        "Calculated SHA-256 Digest for generated key is: {}",
        hexString
    );
}

#[test]
#[serial]
fn ctx_digest_update() {
    let (ctx, sh) = fixture_token().unwrap();

    // using a simple SHA256 for the test
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let res = ctx.digest_init(sh, &mechanism);
    assert!(
        res.is_ok(),
        "failed to call C_DigestInit({}, {:?}) without parameter: {}",
        sh,
        &mechanism,
        res.unwrap_err()
    );

    let data = String::from("Lorem ipsum tralala").into_bytes();
    let ret = ctx.digest_update(sh, &data);
    assert!(
        ret.is_ok(),
        "failed to call C_DigestUpdate({}, {:?}): {}",
        sh,
        &data,
        ret.unwrap_err()
    );

    let digest = ctx.digest_final(sh);
    assert!(
        digest.is_ok(),
        "failed to call C_DigestFinal({}): {}",
        sh,
        digest.unwrap_err()
    );
    let digest = digest.unwrap();

    // tools like shasum are always printing lower-cased hex strings
    // so let's create one of these
    let hexString = digest
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    println!("Calculated SHA-256 Digest is: {}", hexString);

    // now let's compare! created with:
    // echo -n "Lorem ipsum tralala" | shasum -a 256 -p | awk '{ print $1 }'
    // c4b0c693eb7c30dffc5b8c037342850b95746687a636dc95ecd9d75129277002
    assert_eq!(
        hexString,
        "c4b0c693eb7c30dffc5b8c037342850b95746687a636dc95ecd9d75129277002"
    );
}

#[test]
#[serial]
fn ctx_digest_final() {
    let (ctx, sh) = fixture_token().unwrap();

    // using a simple SHA256 for the test
    let mechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let res = ctx.digest_init(sh, &mechanism);
    assert!(
        res.is_ok(),
        "failed to call C_DigestInit({}, {:?}) without parameter: {}",
        sh,
        &mechanism,
        res.unwrap_err()
    );

    let data1 = String::from("Lorem ipsum").into_bytes();
    let data2 = String::from(" tralala").into_bytes();
    let ret = ctx.digest_update(sh, &data1);
    assert!(
        ret.is_ok(),
        "failed to call C_DigestUpdate({}, {:?}): {}",
        sh,
        &data1,
        ret.unwrap_err()
    );

    let ret = ctx.digest_update(sh, &data2);
    assert!(
        ret.is_ok(),
        "failed to call C_DigestUpdate({}, {:?}): {}",
        sh,
        &data2,
        ret.unwrap_err()
    );

    let digest = ctx.digest_final(sh);
    assert!(
        digest.is_ok(),
        "failed to call C_DigestFinal({}): {}",
        sh,
        digest.unwrap_err()
    );
    let digest = digest.unwrap();

    // tools like shasum are always printing lower-cased hex strings
    // so let's create one of these
    let hexString = digest
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    println!("Calculated SHA-256 Digest is: {}", hexString);

    // now let's compare! created with:
    // echo -n "Lorem ipsum tralala" | shasum -a 256 -p | awk '{ print $1 }'
    // c4b0c693eb7c30dffc5b8c037342850b95746687a636dc95ecd9d75129277002
    assert_eq!(
        hexString,
        "c4b0c693eb7c30dffc5b8c037342850b95746687a636dc95ecd9d75129277002"
    );

    // final should have completed the operation
    // so we should be able to start another one
    let res = ctx.digest_init(sh, &mechanism);
    assert!(
        res.is_ok(),
        "failed to call C_DigestInit({}, {:?}) without parameter: {}",
        sh,
        &mechanism,
        res.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_digest_encrypt_update() {
    let (ctx, sh, _, secOh) = fixture_token_and_secret_keys().unwrap();

    // plaintext is padded to one block of data: 16 bytes
    let plaintext1 = String::from("encrypt me 1    ").into_bytes();
    let plaintext2 = String::from("encrypt me 2    ").into_bytes();

    // check if this function is supported first
    let res = ctx.digest_encrypt_update(sh, &plaintext1);
    assert!(res.is_err());
    if let Error::Pkcs11(CKR_FUNCTION_NOT_SUPPORTED) = res.unwrap_err() {
        println!("SoftHSM does not support C_DigestEncryptUpdate at the moment");
        return;
    }

    let encryptMechanism = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let res = ctx.encrypt_init(sh, &encryptMechanism, secOh);
    assert!(
        res.is_ok(),
        "failed to call C_EncryptInit({}, {:?}, {}) without parameter: {}",
        sh,
        &encryptMechanism,
        secOh,
        res.unwrap_err()
    );

    let digestMechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let res = ctx.digest_init(sh, &digestMechanism);
    assert!(
        res.is_ok(),
        "failed to call C_DigestInit({}, {:?}) without parameter: {}",
        sh,
        &digestMechanism,
        res.unwrap_err()
    );

    let ciphertext1 = ctx.digest_encrypt_update(sh, &plaintext1);
    assert!(
        ciphertext1.is_ok(),
        "failed to call C_DigestEncryptUpdate({}, {:?}): {}",
        sh,
        &plaintext1,
        ciphertext1.unwrap_err()
    );
    let ciphertext1 = ciphertext1.unwrap();

    let ciphertext2 = ctx.digest_encrypt_update(sh, &plaintext2);
    assert!(
        ciphertext2.is_ok(),
        "failed to call C_DigestEncryptUpdate({}, {:?}): {}",
        sh,
        &plaintext2,
        ciphertext2.unwrap_err()
    );
    let ciphertext2 = ciphertext2.unwrap();

    let digest = ctx.digest_final(sh);
    assert!(
        digest.is_ok(),
        "failed to call C_DigestFinal({}): {}",
        sh,
        digest.unwrap_err()
    );

    let res = ctx.encrypt_final(sh);
    assert!(
        res.is_ok(),
        "failed to call C_EncryptFinal({}): {}",
        sh,
        res.unwrap_err()
    );
    let res = res.unwrap();
    assert_eq!(res.len(), 0);
    println!("Ciphertexts are: {:?}, {:?}", ciphertext1, ciphertext2);
}

#[test]
#[serial]
fn ctx_decrypt_digest_update() {
    let (ctx, sh, _, secOh) = fixture_token_and_secret_keys().unwrap();

    // plaintext is padded to one block of data: 16 bytes
    let plaintext1Str = "encrypt me 1    ";
    let plaintext2Str = "encrypt me 2    ";
    let plaintext1 = String::from(plaintext1Str).into_bytes();
    let plaintext2 = String::from(plaintext2Str).into_bytes();

    // check if this function is supported first
    let res = ctx.decrypt_digest_update(sh, &plaintext1);
    assert!(res.is_err());
    if let Error::Pkcs11(CKR_FUNCTION_NOT_SUPPORTED) = res.unwrap_err() {
        println!("SoftHSM does not support C_DecryptDigestUpdate at the moment");
        return;
    }

    let encryptMechanism = CK_MECHANISM {
        mechanism: CKM_AES_ECB,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let res = ctx.encrypt_init(sh, &encryptMechanism, secOh);
    assert!(
        res.is_ok(),
        "failed to call C_EncryptInit({}, {:?}, {}) without parameter: {}",
        sh,
        &encryptMechanism,
        secOh,
        res.unwrap_err()
    );

    let digestMechanism = CK_MECHANISM {
        mechanism: CKM_SHA256,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    let res = ctx.digest_init(sh, &digestMechanism);
    assert!(
        res.is_ok(),
        "failed to call C_DigestInit({}, {:?}) without parameter: {}",
        sh,
        &digestMechanism,
        res.unwrap_err()
    );

    let ciphertext1 = ctx.digest_encrypt_update(sh, &plaintext1);
    assert!(
        ciphertext1.is_ok(),
        "failed to call C_DigestEncryptUpdate({}, {:?}): {}",
        sh,
        &plaintext1,
        ciphertext1.unwrap_err()
    );
    let ciphertext1 = ciphertext1.unwrap();

    let ciphertext2 = ctx.digest_encrypt_update(sh, &plaintext2);
    assert!(
        ciphertext2.is_ok(),
        "failed to call C_DigestEncryptUpdate({}, {:?}): {}",
        sh,
        &plaintext2,
        ciphertext2.unwrap_err()
    );
    let ciphertext2 = ciphertext2.unwrap();

    let digest = ctx.digest_final(sh);
    assert!(
        digest.is_ok(),
        "failed to call C_DigestFinal({}): {}",
        sh,
        digest.unwrap_err()
    );

    let res = ctx.encrypt_final(sh);
    assert!(
        res.is_ok(),
        "failed to call C_EncryptFinal({}): {}",
        sh,
        res.unwrap_err()
    );
    let res = res.unwrap();
    assert_eq!(res.len(), 0);
    println!("Ciphertexts are: {:?}, {:?}", ciphertext1, ciphertext2);

    // NOW DECRYPT AND DIGEST
    let res = ctx.decrypt_init(sh, &encryptMechanism, secOh);
    assert!(
        res.is_ok(),
        "failed to call C_DecryptInit({}, {:?}, {}) without parameter: {}",
        sh,
        &encryptMechanism,
        secOh,
        res.unwrap_err()
    );

    let res = ctx.digest_init(sh, &digestMechanism);
    assert!(
        res.is_ok(),
        "failed to call C_DigestInit({}, {:?}) without parameter: {}",
        sh,
        &digestMechanism,
        res.unwrap_err()
    );

    let decryptedPlaintext1 = ctx.decrypt_digest_update(sh, &ciphertext1);
    assert!(
        decryptedPlaintext1.is_ok(),
        "failed to call C_DecryptDigestUpdate({}, {:?}): {}",
        sh,
        &ciphertext1,
        decryptedPlaintext1.unwrap_err()
    );
    let decryptedPlaintext1 = decryptedPlaintext1.unwrap();
    let decryptedPlaintext1 = String::from_utf8_lossy(&decryptedPlaintext1);

    let decryptedPlaintext2 = ctx.decrypt_digest_update(sh, &ciphertext2);
    assert!(
        decryptedPlaintext2.is_ok(),
        "failed to call C_DecryptDigestUpdate({}, {:?}): {}",
        sh,
        &ciphertext2,
        decryptedPlaintext2.unwrap_err()
    );
    let decryptedPlaintext2 = decryptedPlaintext2.unwrap();
    let decryptedPlaintext2 = String::from_utf8_lossy(&decryptedPlaintext2);

    let digest = ctx.digest_final(sh);
    assert!(
        digest.is_ok(),
        "failed to call C_DigestFinal({}): {}",
        sh,
        digest.unwrap_err()
    );

    let res = ctx.decrypt_final(sh);
    assert!(
        res.is_ok(),
        "failed to call C_DecryptFinal({}): {}",
        sh,
        res.unwrap_err()
    );
    let res = res.unwrap();
    assert_eq!(res.len(), 0);

    assert_eq!(decryptedPlaintext1.as_ref(), plaintext1Str);
    assert_eq!(decryptedPlaintext2.as_ref(), plaintext2Str);
}

#[test]
#[serial]
fn ctx_sign_encrypt_update() {
    let (ctx, sh, _, _) = fixture_token_and_key_pair().unwrap();

    let data = String::from("Lorem ipsum tralala").into_bytes();

    // check if this function is supported first
    let res = ctx.sign_encrypt_update(sh, &data);
    assert!(res.is_err());
    if let Error::Pkcs11(CKR_FUNCTION_NOT_SUPPORTED) = res.unwrap_err() {
        println!("SoftHSM does not support C_SignEncryptUpdate at the moment");
        return;
    }
    panic!("TODO: SoftHSM supports C_SignEncryptUpdate now, complete tests")
}

#[test]
#[serial]
fn ctx_decrypt_verify_update() {
    let (ctx, sh, _, _) = fixture_token_and_key_pair().unwrap();

    let data = String::from("Lorem ipsum tralala").into_bytes();

    // check if this function is supported first
    let res = ctx.decrypt_verify_update(sh, data);
    assert!(res.is_err());
    if let Error::Pkcs11(CKR_FUNCTION_NOT_SUPPORTED) = res.unwrap_err() {
        println!("SoftHSM does not support C_DecryptVerifyUpdate at the moment");
        return;
    }
    panic!("TODO: SoftHSM supports C_DecryptVerifyUpdate now, complete tests")
}

#[test]
#[serial]
fn ctx_derive_key() {
    let (ctx, sh) = fixture_token().unwrap();

    // 1. generate 2 DH KeyPairs
    let (pubOh1, privOh1) = fixture_dh_key_pair(
        &ctx,
        sh,
        String::from("label1-pub"),
        String::from("label1-priv"),
    )
    .unwrap();
    let (pubOh2, privOh2) = fixture_dh_key_pair(
        &ctx,
        sh,
        String::from("label2-pub"),
        String::from("label2-priv"),
    )
    .unwrap();

    // 2. retrieve the public key bytes from both
    let mut template = vec![CK_ATTRIBUTE::new(CKA_VALUE)];
    ctx.get_attribute_value(sh, pubOh1, &mut template).unwrap();
    let value: Vec<CK_BYTE> = Vec::with_capacity(template[0].ulValueLen.try_into().unwrap());
    template[0].set_bytes(&value.as_slice());
    ctx.get_attribute_value(sh, pubOh1, &mut template).unwrap();

    let pub1Bytes = template[0].get_bytes().unwrap();

    let mut template = vec![CK_ATTRIBUTE::new(CKA_VALUE)];
    ctx.get_attribute_value(sh, pubOh2, &mut template).unwrap();
    let value: Vec<CK_BYTE> = Vec::with_capacity(template[0].ulValueLen.try_into().unwrap());
    template[0].set_bytes(&value.as_slice());
    ctx.get_attribute_value(sh, pubOh2, &mut template).unwrap();

    let pub2Bytes = template[0].get_bytes().unwrap();

    // 3. derive the first secret key
    let mechanism = CK_MECHANISM {
        mechanism: CKM_DH_PKCS_DERIVE,
        pParameter: pub2Bytes.as_slice().as_ptr() as CK_VOID_PTR,
        ulParameterLen: pub2Bytes.len().try_into().unwrap(),
    };

    let class = CKO_SECRET_KEY;
    let keyType = CKK_AES;
    let valueLen = 32;
    let label = String::from("derived-key-1");
    let token: CK_BBOOL = CK_TRUE;
    let private: CK_BBOOL = CK_TRUE;
    let sensitive: CK_BBOOL = CK_FALSE;
    let extractable: CK_BBOOL = CK_TRUE;

    let template = vec![
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&class),
        CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&keyType),
        CK_ATTRIBUTE::new(CKA_VALUE_LEN).with_ck_ulong(&valueLen),
        CK_ATTRIBUTE::new(CKA_LABEL).with_string(&label),
        CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&token),
        CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&private),
        CK_ATTRIBUTE::new(CKA_SENSITIVE).with_bool(&sensitive),
        CK_ATTRIBUTE::new(CKA_EXTRACTABLE).with_bool(&extractable),
    ];

    let res = ctx.derive_key(sh, &mechanism, privOh1, &template);
    assert!(
        res.is_ok(),
        "failed to call C_DeriveKey({}, {:?}, {}, {:?}): {}",
        sh,
        &mechanism,
        privOh1,
        &template,
        res.unwrap_err()
    );
    let secOh1 = res.unwrap();
    println!("1st Derived Secret Key Object Handle: {}", secOh1);

    // 4. derive the second secret key
    let mechanism = CK_MECHANISM {
        mechanism: CKM_DH_PKCS_DERIVE,
        pParameter: pub1Bytes.as_slice().as_ptr() as CK_VOID_PTR,
        ulParameterLen: pub1Bytes.len().try_into().unwrap(),
    };

    let class = CKO_SECRET_KEY;
    let keyType = CKK_AES;
    let valueLen = 32;
    let label = String::from("derived-key-2");
    let token: CK_BBOOL = CK_TRUE;
    let private: CK_BBOOL = CK_TRUE;
    let sensitive: CK_BBOOL = CK_FALSE;
    let extractable: CK_BBOOL = CK_TRUE;

    let template = vec![
        CK_ATTRIBUTE::new(CKA_CLASS).with_ck_ulong(&class),
        CK_ATTRIBUTE::new(CKA_KEY_TYPE).with_ck_ulong(&keyType),
        CK_ATTRIBUTE::new(CKA_VALUE_LEN).with_ck_ulong(&valueLen),
        CK_ATTRIBUTE::new(CKA_LABEL).with_string(&label),
        CK_ATTRIBUTE::new(CKA_TOKEN).with_bool(&token),
        CK_ATTRIBUTE::new(CKA_PRIVATE).with_bool(&private),
        CK_ATTRIBUTE::new(CKA_SENSITIVE).with_bool(&sensitive),
        CK_ATTRIBUTE::new(CKA_EXTRACTABLE).with_bool(&extractable),
    ];

    let res = ctx.derive_key(sh, &mechanism, privOh2, &template);
    assert!(
        res.is_ok(),
        "failed to call C_DeriveKey({}, {:?}, {}, {:?}): {}",
        sh,
        &mechanism,
        privOh2,
        &template,
        res.unwrap_err()
    );
    let secOh2 = res.unwrap();
    println!("2nd Derived Secret Key Object Handle: {}", secOh2);

    // 5. retrieve the derived private keys from both
    let mut template = vec![CK_ATTRIBUTE::new(CKA_VALUE)];
    ctx.get_attribute_value(sh, secOh1, &mut template).unwrap();
    let value: Vec<CK_BYTE> = Vec::with_capacity(template[0].ulValueLen.try_into().unwrap());
    template[0].set_bytes(&value.as_slice());
    ctx.get_attribute_value(sh, secOh1, &mut template).unwrap();

    let sec1Bytes = template[0].get_bytes().unwrap();

    let mut template = vec![CK_ATTRIBUTE::new(CKA_VALUE)];
    ctx.get_attribute_value(sh, secOh2, &mut template).unwrap();
    let value: Vec<CK_BYTE> = Vec::with_capacity(template[0].ulValueLen.try_into().unwrap());
    template[0].set_bytes(&value.as_slice());
    ctx.get_attribute_value(sh, secOh2, &mut template).unwrap();

    let sec2Bytes = template[0].get_bytes().unwrap();

    println!("1st Derived Key Bytes: {:?}", sec1Bytes);
    println!("2nd Derived Key Bytes: {:?}", sec2Bytes);
    assert_eq!(sec1Bytes, sec2Bytes, "Derived Secret Keys don't match");
}

#[test]
#[serial]
fn ctx_seed_random() {
    let (ctx, sh) = fixture_token().unwrap();

    let seed: Vec<CK_BYTE> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
    let res = ctx.seed_random(sh, &seed);
    assert!(
        res.is_ok(),
        "failed to call C_SeedRandom({}, {:?}): {}",
        sh,
        &seed,
        res.unwrap_err()
    );
}

#[test]
#[serial]
fn ctx_generate_random() {
    let (ctx, sh) = fixture_token().unwrap();
    let res = ctx.generate_random(sh, 32);
    assert!(
        res.is_ok(),
        "failed to call C_GenerateRandom({}, {}): {}",
        sh,
        32,
        res.unwrap_err()
    );
    let randomData = res.unwrap();
    println!("Randomly Generated Data: {:?}", randomData);
}

#[test]
#[serial]
fn ctx_get_function_status() {
    let (ctx, sh) = fixture_token().unwrap();
    let res = ctx.get_function_status(sh);
    assert!(
        res.is_ok(),
        "failed to call C_GetFunctionStatus({}): {}",
        sh,
        res.unwrap_err()
    );
    let val = res.unwrap();
    assert_eq!(val, CKR_FUNCTION_NOT_PARALLEL);
}

#[test]
#[serial]
fn ctx_cancel_function() {
    let (ctx, sh) = fixture_token().unwrap();
    let res = ctx.cancel_function(sh);
    assert!(
        res.is_ok(),
        "failed to call C_CancelFunction({}): {}",
        sh,
        res.unwrap_err()
    );
    let val = res.unwrap();
    assert_eq!(val, CKR_FUNCTION_NOT_PARALLEL);
}

#[test]
#[serial]
fn ctx_wait_for_slot_event() {
    let (ctx, _) = fixture_token().unwrap();

    // this is supported only starting from SoftHSM v2.6.0
    let info = ctx.get_info();
    assert!(
        info.is_ok(),
        "failed to call C_GetInfo: {}",
        info.unwrap_err()
    );
    let info = info.unwrap();
    if info.libraryVersion.major >= 2 && info.libraryVersion.minor >= 6 {
        println!("SoftHSM >= 2.6.0: C_WaitForSlotEvent is supported");
    } else {
        return;
    }
    println!("Running C_WaitForSlotEvent...");

    let slotID = ctx.wait_for_slot_event(CKF_DONT_BLOCK);
    assert!(
        slotID.is_ok(),
        "failed to call C_WaitForSlotEvent({}): {}",
        CKF_DONT_BLOCK,
        slotID.unwrap_err()
    );
    let slotID = slotID.unwrap();
    println!("Wait For Slot Event returned: {:?}", slotID);

    // at this point we did not expect any event
    assert_eq!(slotID, None);

    // TODO: think about what the best way is to generate a slot event in SoftHSM
}

#[test]
#[serial]
fn ctx_get_invalid_attribute_value() {
    {
        let (ctx, sh, oh) = fixture_token_and_object().unwrap();

        // Wrong size to trigger an error.
        let label: String = String::with_capacity(1);
        // Length is not important as it should fail before: the attribute does not exist in the
        // object.
        let public_exponent: Vec<CK_BYTE> = Vec::with_capacity(3);

        let mut template = vec![
            CK_ATTRIBUTE::new(CKA_LABEL),
            CK_ATTRIBUTE::new(CKA_PUBLIC_EXPONENT),
        ];

        template[0].set_string(&label);
        template[1].set_bytes(&public_exponent.as_slice());

        println!("Template: {:?}", template);

        let res = ctx.get_attribute_value(sh, oh, &mut template);
        if !res.is_ok() {
            // Doing this not as an assert so we can both unwrap_err with the mut template and re-borrow template
            let err = res.unwrap_err();
            panic!(
                "failed to call C_GetAttributeValue({}, {}, {:?}): {}",
                sh, oh, &template, err
            );
        }
        let (rv, _) = res.unwrap();
        println!("CK_RV: 0x{:x}, Template: {:?}", rv, &template);

        template[0].get_string().unwrap_err();
        template[1].get_bytes().unwrap_err();
    }
    println!("The end");
}
