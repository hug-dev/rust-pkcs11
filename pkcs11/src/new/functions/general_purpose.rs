use crate::get_pkcs11;
use crate::new::types::function::Rv;
use crate::new::types::locking::CInitializeArgs;
use crate::new::Pkcs11;
use crate::new::Result;
use pkcs11_sys::CK_C_INITIALIZE_ARGS;
use std::ptr;

impl Pkcs11 {
    pub fn initialize(&self, init_args: CInitializeArgs) -> Result<()> {
        // if no args are specified, library expects NULL
        let mut init_args = CK_C_INITIALIZE_ARGS::from(init_args);
        let init_args_ptr = &mut init_args;
        unsafe {
            Rv::from(get_pkcs11!(self, C_Initialize)(
                init_args_ptr as *mut CK_C_INITIALIZE_ARGS as *mut ::std::ffi::c_void,
            ))
            .into_result()
        }
    }

    /// # Safety
    ///
    /// TODO
    pub unsafe fn finalize(&self) -> Result<()> {
        Rv::from(get_pkcs11!(self, C_Finalize)(ptr::null_mut())).into_result()
    }
}
