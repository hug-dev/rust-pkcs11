use pkcs11_sys::CK_SESSION_HANDLE;

#[derive(Debug)]
pub struct Session {
    handle: CK_SESSION_HANDLE,
}

impl Session {
    pub(crate) fn handle(&self) -> CK_SESSION_HANDLE {
        self.handle
    }
}

pub enum UserType {
    So,
    User,
    ContextSpecific,
}
