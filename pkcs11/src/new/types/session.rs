use crate::new::Pkcs11;
use log::error;
use pkcs11_sys::*;

pub struct Session<'a> {
    handle: CK_SESSION_HANDLE,
    client: &'a Pkcs11,
}

impl<'a> Session<'a> {
    pub(crate) fn new(handle: CK_SESSION_HANDLE, client: &'a Pkcs11) -> Self {
        Session { handle, client }
    }

    pub(crate) fn handle(&self) -> CK_SESSION_HANDLE {
        self.handle
    }

    pub(crate) fn client(&self) -> &Pkcs11 {
        self.client
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.close_private() {
            error!("Failed to close session: {}", e);
        }
    }
}

pub enum UserType {
    So,
    User,
    ContextSpecific,
}

impl From<UserType> for CK_USER_TYPE {
    fn from(user_type: UserType) -> CK_USER_TYPE {
        match user_type {
            UserType::So => CKU_SO,
            UserType::User => CKU_USER,
            UserType::ContextSpecific => CKU_CONTEXT_SPECIFIC,
        }
    }
}
