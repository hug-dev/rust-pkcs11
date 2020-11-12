use crate::new::types::slot_token::Slot;
use crate::new::Pkcs11;
use crate::new::Result;

impl Pkcs11 {
    pub fn get_slots_with_token(&self) -> Result<Vec<Slot>> {
        Ok(Vec::new())
    }

    pub fn get_all_slots(&self) -> Result<Vec<Slot>> {
        Ok(Vec::new())
    }
}
