use crate::new::types::session::{Session, UserType};
use crate::new::types::Flags;
use crate::new::types::slot_token::Slot;
use crate::new::types::function::{Result, Rv};

impl Session {
    pub fn open(&self, slot_id: Slot, flags: Flags) -> Result<Session> {
        Err(Rv::Ok)
    }

    pub fn login(&self, user_type: UserType, pin: String) -> Result<()> {
        Err(Rv::Ok)
    }

    pub fn logout(&self) -> Result<()> {
        Err(Rv::Ok)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // close session
    }
}
