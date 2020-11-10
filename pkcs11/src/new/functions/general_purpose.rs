use crate::new::types::function::Rv;
use crate::new::types::locking::CInitializeArgs;
use crate::new::Pkcs11;
use crate::new::{Error, Result};
use pkcs11_sys::{CKR_OK, CK_C_INITIALIZE_ARGS};
use std::ptr;

impl Pkcs11 {
    pub fn initialize(&self, init_args: CInitializeArgs) -> Result<()> {
        // if no args are specified, library expects NULL
        let mut init_args = CK_C_INITIALIZE_ARGS::from(init_args);
        let init_args_ptr = &mut init_args;
        match unsafe {
            ((*self.function_list).C_Initialize.unwrap())(
                init_args_ptr as *mut CK_C_INITIALIZE_ARGS as *mut ::std::ffi::c_void,
            )
        } {
            CKR_OK => Ok(()),
            _err => Err(Error::Pkcs11(Rv::Ok)),
        }
    }

    pub unsafe fn finalize(&self) -> Result<()> {
        match unsafe { ((*self.function_list).C_Finalize.unwrap())(ptr::null_mut()) } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(Rv::Ok)),
        }
    }
}
