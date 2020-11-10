use crate::new::types::mechanism::Mechanism;
use crate::new::types::session::SessionHandle;
use crate::new::Pkcs11;

impl Pkcs11 {
    pub fn generate_key_pair<'a>(
        &self,
        session: SessionHandle,
        mechanism: Mechanism,
        pub_key_template: &[Attribute],
        priv_key_template: &[Attribute],
    ) -> Result<(ObjectHandle, ObjectHandle), Error> {
        Ok(())
    }
}
