use crate::get_pkcs11;
use crate::new::types::function::Rv;
use crate::new::types::session::{Session, UserType};
use crate::new::types::slot_token::Slot;
use crate::new::types::Flags;
use crate::new::Pkcs11;
use crate::new::Result;

impl Pkcs11 {
    pub fn open_session_no_callback(&self, slot_id: Slot, flags: Flags) -> Result<Session> {
        let mut session_handle = 0;

        unsafe {
            Rv::from(get_pkcs11!(self, C_OpenSession)(
                slot_id.id(),
                flags.into(),
                // TODO: abstract those types or create new functions for callbacks
                std::ptr::null_mut(),
                None,
                &mut session_handle,
            ))
            .into_result()?;
        }

        Ok(Session::new(session_handle, &self, slot_id))
    }
}

impl<'a> Session<'a> {
    pub fn close(&self) {}

    pub(crate) fn close_private(&self) -> Result<()> {
        unsafe { Rv::from(get_pkcs11!(self.client(), C_CloseSession)(self.handle())).into_result() }
    }

    // Do not fail if the user is already logged in. It happens if another session on the same slot
    // has already called the log in operation. Record the login call and only log out when there
    // aren't anymore sessions requiring log in state.
    pub fn login(&self, user_type: UserType) -> Result<()> {
        self.client().login(self, user_type)
    }

    pub fn logout(&self) -> Result<()> {
        self.client().logout(self)
    }
}
