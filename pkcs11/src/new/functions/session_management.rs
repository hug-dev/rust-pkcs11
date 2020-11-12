use crate::new::types::function::RvError;
use crate::new::types::session::{Session, UserType};
use crate::new::types::slot_token::Slot;
use crate::new::types::Flags;
use crate::new::Pkcs11;
use crate::new::Result;

impl Pkcs11 {
    pub fn open_session(&self, _slot_id: &Slot, _flags: Flags) -> Result<Session> {
        Err(RvError::GeneralError.into())
    }

    pub fn close_session(&self, _session: Session) -> Result<()> {
        Err(RvError::GeneralError.into())
    }

    pub fn login(&self, _session: &Session, _user_type: UserType, _pin: String) -> Result<()> {
        Err(RvError::GeneralError.into())
    }

    pub fn logout(&self, _session: &Session) -> Result<()> {
        Err(RvError::GeneralError.into())
    }
}
