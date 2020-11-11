use crate::errors::Error;
use pkcs11_sys::{CKR_SESSION_HANDLE_INVALID, CK_SESSION_HANDLE};

#[derive(Debug, Clone, Copy)]
pub struct Session {
    handle: CK_SESSION_HANDLE,
}

pub enum UserType {
    So,
    User,
    ContextSpecific,
}
