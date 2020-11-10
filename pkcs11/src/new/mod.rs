pub mod functions;
pub mod objects;
pub mod types;

use pkcs11_sys::CKR_OK;
use std::mem;
use std::path::Path;

pub struct Pkcs11 {
    pkcs11_lib: pkcs11_sys::Pkcs11,
    function_list: *mut pkcs11_sys::_CK_FUNCTION_LIST,
}

impl Pkcs11 {
    pub fn new<P>(filename: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        unsafe {
            let pkcs11_lib = pkcs11_sys::Pkcs11::new(filename.as_ref())
                .map_err(|e| Error::LibraryLoading { err: e })?;
            let mut list = mem::MaybeUninit::uninit();

            if pkcs11_lib.can_call().C_GetFunctionList().is_err() {
                return Err(Error::LibraryLoading {
                    err: libloading::Error::DlOpenUnknown,
                });
            }

            match pkcs11_lib.C_GetFunctionList(list.as_mut_ptr()) {
                CKR_OK => (),
                _err => return Err(Error::Pkcs11(types::function::Rv::Ok)),
            }

            let list_ptr = *list.as_ptr();

            Ok(Pkcs11 {
                pkcs11_lib,
                function_list: list_ptr,
            })
        }
    }
}

#[derive(Debug)]
pub enum Error {
    /// Any error that happens during library loading of the PKCS#11 module is encompassed under
    /// this error. It is a direct forward of the underlying error from libloading.
    LibraryLoading { err: libloading::Error },

    /// All PKCS#11 functions that return non-zero translate to this error. Note though that only true
    /// errors will be returned as such. Some functions that return non-zero values that are not errors
    /// will not be returned as errors. The affected functions are:
    /// `get_attribute_value`, `get_function_status`, `cancel_function` and `wait_for_slot_event`
    Pkcs11(types::function::Rv),
}

impl From<libloading::Error> for Error {
    fn from(err: libloading::Error) -> Error {
        Error::LibraryLoading { err }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
