use crate::new::types::mechanism::Mechanism;
use crate::new::types::object::Object;
use crate::new::types::session::Session;
use crate::new::Pkcs11;
use crate::new::Result;

impl Pkcs11 {
    pub fn decrypt(
        &self,
        _session: &Session,
        _mechanism: Mechanism,
        _key: &Object,
        _encrypted_data: &[u8],
    ) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
}
