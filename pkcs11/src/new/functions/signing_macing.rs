impl Pkcs11 {
    pub fn sign(&self, session: &SessionHandle, mechanism: Mechanism, key: ObjectHandle, data: Vec<u8>) -> Result<Vec<u8>> {
        Ok(())
    }

    pub fn verify(&self, session: &SessionHandle, mechanism: Mechanism, key: ObjectHandle, data: Vec<u8>, signature: Vec<u8>) -> Result<()> {
        Ok(())
    }
}
