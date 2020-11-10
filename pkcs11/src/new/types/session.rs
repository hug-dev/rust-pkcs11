use crate::errors::Error;
use pkcs11_sys::{CKR_SESSION_HANDLE_INVALID, CK_SESSION_HANDLE};

#[derive(Debug, Clone, Copy)]
pub struct SessionHandle(CK_SESSION_HANDLE);

impl SessionHandle {
    pub(crate) fn new(handle: CK_SESSION_HANDLE) -> Result<Self, Error> {
        if handle == 0 {
            Err(Error::Pkcs11(CKR_SESSION_HANDLE_INVALID))
        } else {
            Ok(SessionHandle(handle))
        }
    }

    pub fn handle(&self) -> CK_SESSION_HANDLE {
        self.0
    }
}
