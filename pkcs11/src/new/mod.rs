pub mod functions;
pub mod objects;
pub mod types;

use crate::new::types::function::Rv;
use std::fmt;
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

    /// All PKCS#11 functions that return non-zero translate to this error.
    Pkcs11(types::function::RvError),

    /// This error marks a feature that is not yet supported by the PKCS11 Rust abstraction layer.
    NotSupported,

    /// Error happening while converting types
    TryFromInt(std::num::TryFromIntError),

    TryFromSlice(std::array::TryFromSliceError),

    NulError(std::ffi::NulError),

    BufferTooBig,

    NullFunctionPointer,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::LibraryLoading(e) => write!(f, "libloading error ({})", e),
            Error::Pkcs11(e) => write!(f, "PKCS11 error: {}", e),
            Error::NotSupported => write!(f, "Feature not supported"),
            Error::TryFromInt(e) => write!(f, "Conversion between integers failed ({})", e),
            Error::TryFromSlice(e) => write!(f, "Error converting slice to array ({})", e),
            Error::NulError(e) => write!(f, "An interior nul byte was found ({})", e),
            Error::BufferTooBig => write!(f, "The buffer given for the attribute was too big"),
            Error::NullFunctionPointer => write!(f, "Calling a NULL function pointer"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::LibraryLoading(e) => Some(e),
            Error::TryFromInt(e) => Some(e),
            Error::TryFromSlice(e) => Some(e),
            Error::NulError(e) => Some(e),
            Error::BufferTooBig
            | Error::Pkcs11(_)
            | Error::NotSupported
            | Error::NullFunctionPointer => None,
        }
    }
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

impl From<std::array::TryFromSliceError> for Error {
    fn from(err: std::array::TryFromSliceError) -> Error {
        Error::TryFromSlice(err)
    }
}

impl From<std::ffi::NulError> for Error {
    fn from(err: std::ffi::NulError) -> Error {
        Error::NulError(err)
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(_err: std::convert::Infallible) -> Error {
        unreachable!()
    }
}

pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use crate::new::types::locking::CInitializeArgs;
    use crate::new::types::mechanism::Mechanism;
    use crate::new::types::object::{
        Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass,
    };
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

        let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
        let modulus_bits: u64 = 1024;

        // pub key template
        let pub_key_template = vec![
            Attribute::Token(true.into()),
            Attribute::Private(false.into()),
            Attribute::PublicExponent(public_exponent),
            Attribute::ModulusBits(modulus_bits.into()),
        ];

        // priv key template
        let priv_key_template = vec![Attribute::Token(true.into())];

        // generate a key pair
        let (public, private) = pkcs11
            .generate_key_pair(&session, &mechanism, &pub_key_template, &priv_key_template)
            .unwrap();

        // data to sign
        let data = [0xFF, 0x55, 0xDD];

        // sign something with it
        let signature = pkcs11
            .sign(&session, &Mechanism::RsaPkcs, private, &data)
            .unwrap();

        // verify the signature
        pkcs11
            .verify(&session, &Mechanism::RsaPkcs, public, &data, &signature)
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

        let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
        let modulus_bits: u64 = 1024;

        // pub key template
        let pub_key_template = vec![
            Attribute::Token(true.into()),
            Attribute::Private(false.into()),
            Attribute::PublicExponent(public_exponent),
            Attribute::ModulusBits(modulus_bits.into()),
            Attribute::Encrypt(true.into()),
        ];

        // priv key template
        let priv_key_template = vec![
            Attribute::Token(true.into()),
            Attribute::Decrypt(true.into()),
        ];

        // generate a key pair
        let (public, private) = pkcs11
            .generate_key_pair(&session, &mechanism, &pub_key_template, &priv_key_template)
            .unwrap();

        // data to encrypt
        let data = vec![0xFF, 0x55, 0xDD];

        // encrypt something with it
        let encrypted_data = pkcs11
            .encrypt(&session, &Mechanism::RsaPkcs, public, &data)
            .unwrap();

        // decrypt
        let decrypted_data = pkcs11
            .decrypt(&session, &Mechanism::RsaPkcs, private, &encrypted_data)
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
    fn import_export() {
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

        let public_exponent: Vec<u8> = vec![0x01, 0x00, 0x01];
        let modulus = vec![0xFF; 1024];

        let template = vec![
            Attribute::Token(true.into()),
            Attribute::Private(false.into()),
            Attribute::PublicExponent(public_exponent),
            Attribute::Modulus(modulus.clone()),
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(KeyType::RSA),
            Attribute::Verify(true.into()),
        ];

        {
            // Intentionally forget the object handle to find it later
            let _public_key = pkcs11.create_object(&session, &template).unwrap();
        }

        let is_it_the_public_key = pkcs11.find_objects(&session, &template).unwrap().remove(0);

        let attribute_info = pkcs11
            .get_attribute_info(&session, is_it_the_public_key, &[AttributeType::Modulus])
            .unwrap()
            .remove(0);

        if let AttributeInfo::Available(size) = attribute_info {
            assert_eq!(size, 1024);
        } else {
            panic!("The Modulus attribute was expected to be present.")
        };

        let attr = pkcs11
            .get_attributes(&session, is_it_the_public_key, &[AttributeType::Modulus])
            .unwrap()
            .remove(0);

        if let Attribute::Modulus(modulus_cmp) = attr {
            assert_eq!(modulus[..], modulus_cmp[..]);
        } else {
            panic!("Expected the Modulus attribute.");
        }

        // delete key
        pkcs11
            .destroy_object(&session, is_it_the_public_key)
            .unwrap();

        // log out
        pkcs11.logout(&session).unwrap();

        // close session
        pkcs11.close_session(session).unwrap();
    }
}
