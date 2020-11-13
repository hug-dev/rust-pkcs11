pub mod functions;
pub mod objects;
pub mod types;

use crate::new::types::function::Rv;
use std::mem;
use std::path::Path;

#[macro_export]
macro_rules! get_pkcs11 {
    ($pkcs11:expr, $func_name:ident) => {
        ($pkcs11
            .function_list
            .$func_name
            .ok_or(crate::new::Error::NullFunctionPointer)?)
    };
}

pub struct Pkcs11 {
    // Even if this field is never read, it is needed for the pointers in function_list to remain
    // valid.
    _pkcs11_lib: pkcs11_sys::Pkcs11,
    function_list: pkcs11_sys::_CK_FUNCTION_LIST,
}

impl Pkcs11 {
    pub fn new<P>(filename: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        unsafe {
            let pkcs11_lib =
                pkcs11_sys::Pkcs11::new(filename.as_ref()).map_err(Error::LibraryLoading)?;
            let mut list = mem::MaybeUninit::uninit();

            if pkcs11_lib.can_call().C_GetFunctionList().is_err() {
                return Err(Error::LibraryLoading(libloading::Error::DlOpenUnknown));
            }

            Rv::from(pkcs11_lib.C_GetFunctionList(list.as_mut_ptr())).into_result()?;

            let list_ptr = *list.as_ptr();

            Ok(Pkcs11 {
                _pkcs11_lib: pkcs11_lib,
                function_list: *list_ptr,
            })
        }
    }
}

#[derive(Debug)]
pub enum Error {
    /// Any error that happens during library loading of the PKCS#11 module is encompassed under
    /// this error. It is a direct forward of the underlying error from libloading.
    LibraryLoading(libloading::Error),

    /// All PKCS#11 functions that return non-zero translate to this error. Note though that only true
    /// errors will be returned as such. Some functions that return non-zero values that are not errors
    /// will not be returned as errors. The affected functions are:
    /// `get_attribute_value`, `get_function_status`, `cancel_function` and `wait_for_slot_event`
    Pkcs11(types::function::RvError),

    /// This error marks a feature that is not yet supported by the PKCS11 Rust abstraction layer.
    NotSupported,

    /// Error happening while converting types
    TryFromInt(std::num::TryFromIntError),

    NulError(std::ffi::NulError),

    BufferTooBig,

    NullFunctionPointer,
}

impl From<libloading::Error> for Error {
    fn from(err: libloading::Error) -> Error {
        Error::LibraryLoading(err)
    }
}

impl From<std::num::TryFromIntError> for Error {
    fn from(err: std::num::TryFromIntError) -> Error {
        Error::TryFromInt(err)
    }
}

impl From<std::ffi::NulError> for Error {
    fn from(err: std::ffi::NulError) -> Error {
        Error::NulError(err)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use crate::new::types::locking::CInitializeArgs;
    use crate::new::types::mechanism::Mechanism;
    use crate::new::types::object::Attribute;
    use crate::new::types::session::UserType;
    use crate::new::types::Flags;
    use crate::new::Pkcs11;

    #[test]
    fn sign_verify() {
        let pkcs11 = Pkcs11::new("/usr/local/lib/softhsm/libsofthsm2.so").unwrap();

        // initialize the library
        pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();

        // find a slot, get the first one
        let slot = pkcs11.get_slots_with_token().unwrap().remove(0);

        // set flags
        let mut flags = Flags::new();
        flags.set_rw_session(true).set_serial_session(true);

        // open a session
        let session = pkcs11.open_session_no_callback(&slot, flags).unwrap();

        let pin = String::from("123456");

        // log in the session
        pkcs11.login(&session, UserType::User, &pin).unwrap();

        // get mechanism
        let mechanism = Mechanism::RsaPkcsKeyPairGen;

        let mut attr_true = pkcs11_sys::CK_TRUE;
        let mut attr_true1 = pkcs11_sys::CK_TRUE;
        let mut attr_false = pkcs11_sys::CK_FALSE;
        let mut public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
        let mut modulus_bits: u64 = 1024;

        // pub key template
        let mut pub_key_template = vec![
            Attribute::Token(&mut attr_true),
            Attribute::Private(&mut attr_false),
            Attribute::PublicExponent(&mut public_exponent),
            Attribute::ModulusBits(&mut modulus_bits),
        ];

        // priv key template
        let mut priv_key_template = vec![Attribute::Token(&mut attr_true1)];

        // generate a key pair
        let (public, private) = pkcs11
            .generate_key_pair(
                &session,
                mechanism,
                &mut pub_key_template,
                &mut priv_key_template,
            )
            .unwrap();

        // data to sign
        let mut data = [0xFF, 0x55, 0xDD];

        // sign something with it
        let mut signature = pkcs11
            .sign(&session, Mechanism::RsaPkcs, &private, &mut data)
            .unwrap();

        // verify the signature
        pkcs11
            .verify(
                &session,
                Mechanism::RsaPkcs,
                &public,
                &mut data,
                &mut signature,
            )
            .unwrap();

        // delete keys
        pkcs11.destroy_object(&session, public).unwrap();
        pkcs11.destroy_object(&session, private).unwrap();

        // log out
        pkcs11.logout(&session).unwrap();

        // close session
        pkcs11.close_session(session).unwrap();
    }

    #[test]
    fn encrypt_decrypt() {
        let pkcs11 = Pkcs11::new("/usr/local/lib/softhsm/libsofthsm2.so").unwrap();

        // initialize the library
        pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();

        // find a slot, get the first one
        let slot = pkcs11.get_slots_with_token().unwrap().remove(0);

        // set flags
        let mut flags = Flags::new();
        flags.set_rw_session(true).set_serial_session(true);

        // open a session
        let session = pkcs11.open_session_no_callback(&slot, flags).unwrap();

        let pin = String::from("123456");

        // log in the session
        pkcs11.login(&session, UserType::User, &pin).unwrap();

        // get mechanism
        let mechanism = Mechanism::RsaPkcsKeyPairGen;

        let mut attr_true = pkcs11_sys::CK_TRUE;
        let mut attr_true1 = pkcs11_sys::CK_TRUE;
        let mut attr_true2 = pkcs11_sys::CK_TRUE;
        let mut attr_true3 = pkcs11_sys::CK_TRUE;
        let mut attr_false = pkcs11_sys::CK_FALSE;
        let mut public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
        let mut modulus_bits: u64 = 1024;

        // pub key template
        let mut pub_key_template = vec![
            Attribute::Token(&mut attr_true),
            Attribute::Private(&mut attr_false),
            Attribute::PublicExponent(&mut public_exponent),
            Attribute::ModulusBits(&mut modulus_bits),
            Attribute::Encrypt(&mut attr_true3),
        ];

        // priv key template
        let mut priv_key_template = vec![
            Attribute::Token(&mut attr_true1),
            Attribute::Decrypt(&mut attr_true2),
        ];

        // generate a key pair
        let (public, private) = pkcs11
            .generate_key_pair(
                &session,
                mechanism,
                &mut pub_key_template,
                &mut priv_key_template,
            )
            .unwrap();

        // data to encrypt
        let mut data = vec![0xFF, 0x55, 0xDD];

        // encrypt something with it
        let mut encrypted_data = pkcs11
            .encrypt(&session, Mechanism::RsaPkcs, &public, &mut data)
            .unwrap();

        // decrypt
        let decrypted_data = pkcs11
            .decrypt(&session, Mechanism::RsaPkcs, &private, &mut encrypted_data)
            .unwrap();

        // The decrypted buffer is bigger than the original one.
        assert_eq!(data, decrypted_data);

        // delete keys
        pkcs11.destroy_object(&session, public).unwrap();
        pkcs11.destroy_object(&session, private).unwrap();

        // log out
        pkcs11.logout(&session).unwrap();

        // close session
        pkcs11.close_session(session).unwrap();
    }

    #[test]
    fn import_export() {}
}
