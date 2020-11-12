use crate::new::types::function::{Result, Rv};
use crate::new::types::object::Attribute;
use crate::new::types::object::Object;
use crate::new::types::session::Session;
use crate::new::Pkcs11;
// TODO: get_attribute_value

impl Pkcs11 {
    pub fn find_objects(
        &self,
        _session: &mut Session,
        _template: Option<&[Attribute]>,
    ) -> Result<Vec<Object>> {
        Ok(Vec::new())
    }

    pub fn create_object(&self, _session: &Session, _template: &[Attribute]) -> Result<Object> {
        Err(Rv::Ok)
    }

    pub fn destroy_object(&self, session: &Session, object: Object) -> Result<()> {
        match unsafe {
            ((*self.function_list).C_DestroyObject.unwrap())(session.handle(), object.handle())
        } {
            pkcs11_sys::CKR_OK => Ok(()),
            _err => Ok(()),
        }
    }
}
