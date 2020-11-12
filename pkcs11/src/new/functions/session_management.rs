use crate::new::types::function::{Result, Rv};
use crate::new::types::session::{Session, UserType};
use crate::new::types::slot_token::Slot;
use crate::new::types::Flags;
use crate::new::Pkcs11;

impl Pkcs11 {
    pub fn open_session(&self, _slot_id: &Slot, _flags: Flags) -> Result<Session> {
        Err(Rv::Ok)
    }

    pub fn close_session(&self, _session: Session) -> Result<()> {
        Err(Rv::Ok)
    }

    pub fn login(&self, _session: &Session, _user_type: UserType, _pin: String) -> Result<()> {
        Err(Rv::Ok)
    }

    pub fn logout(&self, _session: &Session) -> Result<()> {
        Err(Rv::Ok)
    }
}
