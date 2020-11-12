use pkcs11_sys::CK_SLOT_ID;

#[derive(Debug)]
pub struct Slot {
    slot_id: u64,
}

impl Slot {
    pub(crate) fn new(slot_id: CK_SLOT_ID) -> Slot {
        Slot { slot_id }
    }

    pub fn id(&self) -> u64 {
        self.slot_id
    }
}
