use crate::get_pkcs11;
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

        Ok(Session::new(session_handle, &self))
    }
}

impl<'a> Session<'a> {
    pub fn close(&self) {}

    pub(crate) fn close_private(&self) -> Result<()> {
        unsafe { Rv::from(get_pkcs11!(self.client(), C_CloseSession)(self.handle())).into_result() }
    }

    pub fn login(&self, user_type: UserType, pin: &str) -> Result<()> {
        //TODO: zeroize after
        let mut pin = CString::new(pin)?.into_bytes();
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_Login)(
                self.handle(),
                user_type.into(),
                pin.as_mut_ptr(),
                pin.len().try_into()?,
            ))
            .into_result()
        }
    }

    pub fn logout(&self) -> Result<()> {
        unsafe { Rv::from(get_pkcs11!(self.client(), C_Logout)(self.handle())).into_result() }
    }
}
