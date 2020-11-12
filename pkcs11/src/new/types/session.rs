use pkcs11_sys::*;

#[derive(Debug)]
pub struct Session {
    handle: CK_SESSION_HANDLE,
}

impl Session {
    pub(crate) fn new(handle: CK_SESSION_HANDLE) -> Self {
        Session { handle }
    }

    pub(crate) fn handle(&self) -> CK_SESSION_HANDLE {
        self.handle
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
