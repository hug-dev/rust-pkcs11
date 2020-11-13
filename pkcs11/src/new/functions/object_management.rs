use crate::new::types::function::{Rv, RvError};
use crate::new::types::object::{Attribute, AttributeInfo, AttributeType, Object};
use crate::new::types::session::Session;
use crate::new::Pkcs11;
use crate::new::{Error, Result};
use log::error;
use pkcs11_sys::*;
use std::convert::TryInto;

// Search 10 elements at a time
const MAX_OBJECT_COUNT: usize = 10;

impl Pkcs11 {
    pub fn find_objects(
        &self,
        session: &mut Session,
        template: &mut [Attribute],
    ) -> Result<Vec<Object>> {
        let mut template: Vec<CK_ATTRIBUTE> = template.iter_mut().map(|attr| attr.into()).collect();

        Rv::from(unsafe {
            ((*self.function_list).C_FindObjectsInit.unwrap())(
                session.handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
            )
        })
        .to_result()?;

        let mut object_handles = [0; MAX_OBJECT_COUNT];
        let mut object_count = 0;
        let mut objects = Vec::new();

        Rv::from(unsafe {
            ((*self.function_list).C_FindObjects.unwrap())(
                session.handle(),
                object_handles.as_mut_ptr() as CK_OBJECT_HANDLE_PTR,
                MAX_OBJECT_COUNT.try_into()?,
                &mut object_count,
            )
        })
        .to_result()?;

        while object_count > 0 {
            objects.extend_from_slice(&object_handles[..object_count.try_into()?]);

            Rv::from(unsafe {
                ((*self.function_list).C_FindObjects.unwrap())(
                    session.handle(),
                    object_handles.as_mut_ptr() as CK_OBJECT_HANDLE_PTR,
                    MAX_OBJECT_COUNT.try_into()?,
                    &mut object_count,
                )
            })
            .to_result()?;
        }

        Rv::from(unsafe { ((*self.function_list).C_FindObjectsFinal.unwrap())(session.handle()) })
            .to_result()?;

        let objects = objects.into_iter().map(Object::new).collect();

        Ok(objects)
    }

    pub fn create_object(&self, session: &Session, template: &mut [Attribute]) -> Result<Object> {
        let mut template: Vec<CK_ATTRIBUTE> = template.iter_mut().map(|attr| attr.into()).collect();
        let mut object_handle = 0;

        Rv::from(unsafe {
            ((*self.function_list).C_CreateObject.unwrap())(
                session.handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
                &mut object_handle as CK_OBJECT_HANDLE_PTR,
            )
        })
        .to_result()?;

        Ok(Object::new(object_handle))
    }

    pub fn destroy_object(&self, session: &Session, object: Object) -> Result<()> {
        Rv::from(unsafe {
            ((*self.function_list).C_DestroyObject.unwrap())(session.handle(), object.handle())
        })
        .to_result()
    }

    // Return without modifying the template if:
    // - any of the attribute if sensitive
    // - any of the attribute does not exist in the object
    // - any of the attribute given is too small to contain the value
    // - any of the attribute given length is bigger than the one required
    pub fn get_attribute_value(
        &self,
        session: &mut Session,
        object: &Object,
        template: &mut [Attribute],
    ) -> Result<()> {
        let mut template: Vec<CK_ATTRIBUTE> = template.iter_mut().map(|attr| attr.into()).collect();

        // Check if the attributes are available and get the length
        let mut test_template: Vec<CK_ATTRIBUTE> = template
            .iter()
            .cloned()
            .map(|mut a| {
                a.pValue = std::ptr::null_mut();
                a
            })
            .collect();

        Rv::from(unsafe {
            ((*self.function_list).C_GetAttributeValue.unwrap())(
                session.handle(),
                object.handle(),
                test_template.as_mut_ptr(),
                test_template.len().try_into()?,
            )
        })
        .to_result()
        .or_else(|e| {
            for attribute in &test_template {
                if attribute.ulValueLen == CK_UNAVAILABLE_INFORMATION {
                    error!("Attribute {} is unavailable.", attribute.type_);
                }
            }
            Err(e)
        })?;

        // Check that the length of the attribute is the same one as in the originial iterator
        template
            .iter()
            .cloned()
            .zip(test_template.into_iter())
            .map(|(given, expected)| {
                if given.ulValueLen < expected.ulValueLen {
                    error!(
                        "Attribute of type {} has a buffer too small. {} expected, {} given.",
                        given.type_, expected.ulValueLen, given.ulValueLen
                    );
                    Err(RvError::BufferTooSmall.into())
                } else if given.ulValueLen > expected.ulValueLen {
                    error!(
                        "Attribute of type {} has a buffer too big. {} expected, {} given.",
                        given.type_, expected.ulValueLen, given.ulValueLen
                    );
                    Err(Error::BufferTooBig)
                } else {
                    Ok(())
                }
            })
            .collect::<Result<()>>()?;

        Rv::from(unsafe {
            ((*self.function_list).C_GetAttributeValue.unwrap())(
                session.handle(),
                object.handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
            )
        })
        // Add a or_else to log what attribute were missing in case of error
        .to_result()
    }

    pub fn get_attribute_info(
        &self,
        session: &mut Session,
        object: &Object,
        attributes: &[AttributeType],
    ) -> Result<Vec<AttributeInfo>> {
        let mut template: Vec<CK_ATTRIBUTE> = attributes
            .iter()
            .map(|attr_type| CK_ATTRIBUTE {
                type_: (*attr_type).into(),
                pValue: std::ptr::null_mut(),
                ulValueLen: 0,
            })
            .collect();

        match Rv::from(unsafe {
            ((*self.function_list).C_GetAttributeValue.unwrap())(
                session.handle(),
                object.handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
            )
        }) {
            Rv::Ok
            | Rv::Error(RvError::AttributeSensitive)
            | Rv::Error(RvError::AttributeTypeInvalid) => Ok(template
                .iter()
                .map(|attr| match attr.ulValueLen {
                    CK_UNAVAILABLE_INFORMATION => Ok(AttributeInfo::Unavailable),
                    len => Ok(AttributeInfo::Available(len.try_into()?)),
                })
                .collect::<Result<Vec<AttributeInfo>>>()?),
            Rv::Error(rv_error) => Err(rv_error.into()),
        }
    }
}
