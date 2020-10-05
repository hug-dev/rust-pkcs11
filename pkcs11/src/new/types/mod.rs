pub mod function;
pub mod locking;
pub mod object;

use pkcs11_sys::CKF_ARRAY_ATTRIBUTE;
use pkcs11_sys::CKF_CLOCK_ON_TOKEN;
use pkcs11_sys::CKF_DECRYPT;
use pkcs11_sys::CKF_DERIVE;
use pkcs11_sys::CKF_DIGEST;
use pkcs11_sys::CKF_DONT_BLOCK;
use pkcs11_sys::CKF_DUAL_CRYPTO_OPERATIONS;
use pkcs11_sys::CKF_EC_COMPRESS;
use pkcs11_sys::CKF_EC_F_P;
use pkcs11_sys::CKF_EC_NAMEDCURVE;
use pkcs11_sys::CKF_EC_UNCOMPRESS;
use pkcs11_sys::CKF_ENCRYPT;
use pkcs11_sys::CKF_EXCLUDE_CHALLENGE;
use pkcs11_sys::CKF_EXCLUDE_COUNTER;
use pkcs11_sys::CKF_EXCLUDE_PIN;
use pkcs11_sys::CKF_EXCLUDE_TIME;
use pkcs11_sys::CKF_EXTENSION;
use pkcs11_sys::CKF_GENERATE;
use pkcs11_sys::CKF_GENERATE_KEY_PAIR;
use pkcs11_sys::CKF_HW; /* performed by HW */
use pkcs11_sys::CKF_HW_SLOT;
use pkcs11_sys::CKF_LIBRARY_CANT_CREATE_OS_THREADS;
use pkcs11_sys::CKF_LOGIN_REQUIRED;
use pkcs11_sys::CKF_NEXT_OTP;
use pkcs11_sys::CKF_OS_LOCKING_OK;
use pkcs11_sys::CKF_PROTECTED_AUTHENTICATION_PATH;
use pkcs11_sys::CKF_REMOVABLE_DEVICE;
use pkcs11_sys::CKF_RESTORE_KEY_NOT_NEEDED;
use pkcs11_sys::CKF_RNG;
use pkcs11_sys::CKF_RW_SESSION;
use pkcs11_sys::CKF_SECONDARY_AUTHENTICATION;
use pkcs11_sys::CKF_SERIAL_SESSION;
use pkcs11_sys::CKF_SIGN;
use pkcs11_sys::CKF_SIGN_RECOVER;
use pkcs11_sys::CKF_SO_PIN_COUNT_LOW;
use pkcs11_sys::CKF_SO_PIN_FINAL_TRY;
use pkcs11_sys::CKF_SO_PIN_LOCKED;
use pkcs11_sys::CKF_SO_PIN_TO_BE_CHANGED;
use pkcs11_sys::CKF_TOKEN_INITIALIZED;
use pkcs11_sys::CKF_TOKEN_PRESENT;
use pkcs11_sys::CKF_UNWRAP;
use pkcs11_sys::CKF_USER_FRIENDLY_OTP;
use pkcs11_sys::CKF_USER_PIN_COUNT_LOW;
use pkcs11_sys::CKF_USER_PIN_FINAL_TRY;
use pkcs11_sys::CKF_USER_PIN_INITIALIZED;
use pkcs11_sys::CKF_USER_PIN_LOCKED;
use pkcs11_sys::CKF_USER_PIN_TO_BE_CHANGED;
use pkcs11_sys::CKF_VERIFY;
use pkcs11_sys::CKF_VERIFY_RECOVER;
use pkcs11_sys::CKF_WRAP;
use pkcs11_sys::CKF_WRITE_PROTECTED;
use pkcs11_sys::CK_FLAGS;

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
