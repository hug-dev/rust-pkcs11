use crate::new::types::function::Result;
use crate::new::types::session::Session;
use crate::new::types::object::Object;
use crate::new::Pkcs11;
use crate::new::types::mechanism::Mechanism;

impl Pkcs11 {
    pub fn decrypt(&self, session: &Session, mechanism: Mechanism, key: &Object, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
}
