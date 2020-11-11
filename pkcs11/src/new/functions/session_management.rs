impl Session {
    pub fn open(&self, slot_id: Slot, flags: Flags) -> Result<Session> {
    }

    pub fn login(&self, user_type: UserType, pin: String) -> Result<()> {
    }

    pub fn logout(&self) -> Result<()> {
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // close session
    }
}
