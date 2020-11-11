use crate::new::types::function::Result;
use crate::new::types::session::Session;
use crate::new::types::object::Object;
use crate::new::Pkcs11;
use crate::new::types::mechanism::Mechanism;

impl Pkcs11 {
    pub fn sign(&self, session: &Session, mechanism: Mechanism, key: Object, data: Vec<u8>) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    pub fn verify(&self, session: &Session, mechanism: Mechanism, key: Object, data: Vec<u8>, signature: Vec<u8>) -> Result<()> {
        Ok(())
    }
}
