use crate::new::types::function::{Rv, RvError};
use crate::new::types::object::Attribute;
use crate::new::types::object::Object;
use crate::new::types::session::Session;
use crate::new::Pkcs11;
use crate::new::Result;
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
        Err(RvError::GeneralError.into())
    }

    pub fn destroy_object(&self, session: &Session, object: Object) -> Result<()> {
        Rv::from(unsafe {
            ((*self.function_list).C_DestroyObject.unwrap())(session.handle(), object.handle())
        })
        .to_result()
    }
}
