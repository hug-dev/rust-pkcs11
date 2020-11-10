impl Pkcs11 {
    pub fn decrypt(&self, session: &SessionHandle, mechanism: Mechanism, key: ObjectHandle, encrypted_data: Vec<u8>) -> Result<Vec<u8>> {
        Ok(())
    }
}
