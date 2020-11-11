// to add: find_objects_init, find_object, find_object_final, create_object, destroy_object,
// get_attribute_value





pub fn destroy_object(
    &self,
    session: SessionHandle,
    object: ObjectHandle,
    ) -> Result<(), Error> {
    match unsafe {
        ((*self.function_list).C_DestroyObject.unwrap())(session.handle(), object.handle())
    } {
        CKR_OK => Ok(()),
        err => Err(Error::Pkcs11(err)),
    }
}
