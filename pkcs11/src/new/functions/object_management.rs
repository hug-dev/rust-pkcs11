use crate::new::types::function::{Result, Rv};
use crate::new::types::session::Session;
use crate::new::types::object::Object;
use crate::new::types::object::Attribute;
use crate::new::Pkcs11;
// TODO: get_attribute_value

impl Pkcs11 {
    pub fn find_objects(&self, session: &mut Session, template: Option<Vec<Attribute>>) -> Result<Vec<Object>> {
        Ok(Vec::new())
    }

    pub fn create_object(&self, session: &Session, template: Vec<Attribute>) -> Result<Object> {
        Err(Rv::Ok)
    }

    pub fn destroy_object(
        &self,
        session: &Session,
        object: Object,
        ) -> Result<()> {
        match unsafe {
            ((*self.function_list).C_DestroyObject.unwrap())(session.handle(), object.handle())
        } {
            CKR_OK => Ok(()),
            err => Ok(()),
        }
    }
}
