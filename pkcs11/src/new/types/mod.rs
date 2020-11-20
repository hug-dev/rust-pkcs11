pub mod function;
pub mod locking;
pub mod mechanism;
pub mod object;
pub mod session;
pub mod slot_token;

use crate::new::{Error, Result};
use log::error;
use pkcs11_sys::*;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::ops::Deref;

#[derive(Default)]
pub struct Flags {
    flags: CK_FLAGS,
}

impl Flags {
    pub fn new() -> Self {
        Flags::default()
    }

    fn set_flag(&mut self, flag: CK_FLAGS, b: bool) {
        if b {
            self.flags |= flag;
        } else {
            self.flags &= !flag;
        }
    }

    pub fn set_token_present(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_TOKEN_PRESENT, b);
        self
    }

    pub fn set_removable_device(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_REMOVABLE_DEVICE, b);
        self
    }

    pub fn set_hw_slot(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_HW_SLOT, b);
        self
    }

    pub fn set_array_attribute(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_ARRAY_ATTRIBUTE, b);
        self
    }

    pub fn set_rng(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_RNG, b);
        self
    }

    pub fn set_write_protected(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_WRITE_PROTECTED, b);
        self
    }

    pub fn set_login_required(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_LOGIN_REQUIRED, b);
        self
    }

    pub fn set_user_pin_initialized(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_INITIALIZED, b);
        self
    }

    pub fn set_restore_key_not_needed(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_RESTORE_KEY_NOT_NEEDED, b);
        self
    }

    pub fn set_clock_on_token(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_CLOCK_ON_TOKEN, b);
        self
    }

    pub fn set_protected_authentication_path(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_PROTECTED_AUTHENTICATION_PATH, b);
        self
    }

    pub fn set_dual_crypto_operations(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DUAL_CRYPTO_OPERATIONS, b);
        self
    }

    pub fn set_token_initialized(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_TOKEN_INITIALIZED, b);
        self
    }

    pub fn set_secondary_authentication(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SECONDARY_AUTHENTICATION, b);
        self
    }

    pub fn set_user_pin_count_low(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_COUNT_LOW, b);
        self
    }

    pub fn set_user_pin_final_try(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_FINAL_TRY, b);
        self
    }

    pub fn set_user_pin_locked(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_LOCKED, b);
        self
    }

    pub fn set_user_pin_to_be_changed(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_TO_BE_CHANGED, b);
        self
    }

    pub fn set_so_pin_count_low(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SO_PIN_COUNT_LOW, b);
        self
    }

    pub fn set_so_pin_final_try(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SO_PIN_FINAL_TRY, b);
        self
    }

    pub fn set_so_pin_locked(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SO_PIN_LOCKED, b);
        self
    }

    pub fn set_so_pin_to_be_changed(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SO_PIN_TO_BE_CHANGED, b);
        self
    }

    pub fn set_rw_session(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_RW_SESSION, b);
        self
    }

    pub fn set_serial_session(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SERIAL_SESSION, b);
        self
    }

    pub fn set_next_otp(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_NEXT_OTP, b);
        self
    }

    pub fn set_exclude_time(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EXCLUDE_TIME, b);
        self
    }

    pub fn set_exclude_counter(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EXCLUDE_COUNTER, b);
        self
    }

    pub fn set_exclude_challenge(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EXCLUDE_CHALLENGE, b);
        self
    }

    pub fn set_exclude_pin(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EXCLUDE_PIN, b);
        self
    }

    pub fn set_user_friendly_otp(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_FRIENDLY_OTP, b);
        self
    }

    pub fn set_hw(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_HW, b);
        self
    }

    pub fn set_encrypt(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_ENCRYPT, b);
        self
    }

    pub fn set_decrypt(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DECRYPT, b);
        self
    }

    pub fn set_digest(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DIGEST, b);
        self
    }

    pub fn set_sign(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SIGN, b);
        self
    }

    pub fn set_sign_recover(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SIGN_RECOVER, b);
        self
    }

    pub fn set_verify(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_VERIFY, b);
        self
    }

    pub fn set_verify_recover(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_VERIFY_RECOVER, b);
        self
    }

    pub fn set_generate(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_GENERATE, b);
        self
    }

    pub fn set_generate_key_pair(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_GENERATE_KEY_PAIR, b);
        self
    }

    pub fn set_wrap(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_WRAP, b);
        self
    }

    pub fn set_unwrap(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_UNWRAP, b);
        self
    }

    pub fn set_derive(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DERIVE, b);
        self
    }

    pub fn set_extension(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EXTENSION, b);
        self
    }

    pub fn set_ec_f_p(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EC_F_P, b);
        self
    }

    pub fn set_ec_namedcurve(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EC_NAMEDCURVE, b);
        self
    }

    pub fn set_ec_uncompress(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EC_UNCOMPRESS, b);
        self
    }

    pub fn set_ec_compress(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EC_COMPRESS, b);
        self
    }

    pub fn set_dont_block(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DONT_BLOCK, b);
        self
    }

    pub fn set_library_cant_create_os_threads(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_LIBRARY_CANT_CREATE_OS_THREADS, b);
        self
    }

    pub fn set_os_locking_ok(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_OS_LOCKING_OK, b);
        self
    }
}

impl From<Flags> for pkcs11_sys::CK_FLAGS {
    fn from(flags: Flags) -> Self {
        flags.flags
    }
}

#[repr(u8)]
#[derive(Debug)]
pub enum Bbool {
    False = 0,
    True = 1,
}

impl TryFrom<&[u8]> for Bbool {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self> {
        CK_BBOOL::from_ne_bytes(slice.try_into()?).try_into()
    }
}

impl From<Bbool> for CK_BBOOL {
    fn from(bbool: Bbool) -> Self {
        bbool as CK_BBOOL
    }
}

impl From<bool> for Bbool {
    fn from(val: bool) -> Self {
        if val {
            Bbool::True
        } else {
            Bbool::False
        }
    }
}

impl TryFrom<CK_BBOOL> for Bbool {
    type Error = Error;

    fn try_from(bbool: CK_BBOOL) -> Result<Self> {
        match bbool {
            CK_FALSE => Ok(Bbool::False),
            CK_TRUE => Ok(Bbool::True),
            other => {
                error!("Bbool value {} is not supported.", other);
                Err(Error::NotSupported)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Ulong {
    val: CK_ULONG,
}

impl Deref for Ulong {
    type Target = CK_ULONG;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl From<Ulong> for CK_ULONG {
    fn from(ulong: Ulong) -> Self {
        *ulong
    }
}

impl From<CK_ULONG> for Ulong {
    fn from(ulong: CK_ULONG) -> Self {
        Ulong { val: ulong }
    }
}
