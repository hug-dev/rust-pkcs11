// to add: find_objects_init, find_object, find_object_final, create_object, destroy_object,
// get_attribute_value

impl Pkcs11 {
    pub fn find_objects(&self, session: &mut Session, template: Option<Vec<Attribute>>) -> Result<Vec<Object>> {
    }

    pub fn create_object(&self, session: &Session, template: Vec<Attribute>) -> Result<Object> {
    }

    pub fn destroy_object(
        &self,
        session: &Session,
        object: ObjectHandle,
        ) -> Result<()> {
        match unsafe {
            ((*self.function_list).C_DestroyObject.unwrap())(session.handle(), object.handle())
        } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }
}
