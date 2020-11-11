impl Pkcs11 {
    pub fn encrypt(&self, session: &SessionHandle, mechanism: Mechanism, key: ObjectHandle, data: Vec<u8>) -> Result<Vec<u8>> {
        Ok(())
    }
}
