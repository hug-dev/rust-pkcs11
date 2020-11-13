use crate::new::types::function::Rv;
use crate::new::types::session::{Session, UserType};
use crate::new::types::slot_token::Slot;
use crate::new::types::Flags;
use crate::new::Pkcs11;
use crate::new::Result;
use std::convert::TryInto;
use std::ffi::CString;

impl Pkcs11 {
    pub fn open_session_no_callback(&self, slot_id: &Slot, flags: Flags) -> Result<Session> {
        let mut session_handle = 0;

        Rv::from(unsafe {
            ((*self.function_list).C_OpenSession.unwrap())(
                slot_id.id(),
                flags.into(),
                // TODO: abstract those types or create new functions for callbacks
                std::ptr::null_mut(),
                None,
                &mut session_handle,
            )
        })
        .to_result()?;

        Ok(Session::new(session_handle))
    }

    pub fn close_session(&self, session: Session) -> Result<()> {
        Rv::from(unsafe { ((*self.function_list).C_CloseSession.unwrap())(session.handle()) })
            .to_result()
    }

    pub fn login(&self, session: &Session, user_type: UserType, pin: &str) -> Result<()> {
        //TODO: zeroize after
        let mut pin = CString::new(pin)?.into_bytes();
        Rv::from(unsafe {
            ((*self.function_list).C_Login.unwrap())(
                session.handle(),
                user_type.into(),
                pin.as_mut_ptr(),
                pin.len().try_into()?,
            )
        })
        .to_result()
    }

    pub fn logout(&self, session: &Session) -> Result<()> {
        Rv::from(unsafe { ((*self.function_list).C_Logout.unwrap())(session.handle()) }).to_result()
    }
}
