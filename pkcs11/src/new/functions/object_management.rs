//! Object management functions

use crate::get_pkcs11;
use crate::new::types::function::{Rv, RvError};
use crate::new::types::object::{Attribute, AttributeInfo, AttributeType, ObjectHandle};
use crate::new::types::session::Session;
use crate::new::Result;
use pkcs11_sys::*;
use std::convert::TryInto;

// Search 10 elements at a time
const MAX_OBJECT_COUNT: usize = 10;

impl<'a> Session<'a> {
    /// Search for session objects matching a template
    pub fn find_objects(&self, template: &[Attribute]) -> Result<Vec<ObjectHandle>> {
        let mut template: Vec<CK_ATTRIBUTE> = template.iter().map(|attr| attr.into()).collect();

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_FindObjectsInit)(
                self.handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
            ))
            .into_result()?;
        }

        let mut object_handles = [0; MAX_OBJECT_COUNT];
        let mut object_count = 0;
        let mut objects = Vec::new();

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_FindObjects)(
                self.handle(),
                object_handles.as_mut_ptr() as CK_OBJECT_HANDLE_PTR,
                MAX_OBJECT_COUNT.try_into()?,
                &mut object_count,
            ))
            .into_result()?;
        }

        while object_count > 0 {
            objects.extend_from_slice(&object_handles[..object_count.try_into()?]);

            unsafe {
                Rv::from(get_pkcs11!(self.client(), C_FindObjects)(
                    self.handle(),
                    object_handles.as_mut_ptr() as CK_OBJECT_HANDLE_PTR,
                    MAX_OBJECT_COUNT.try_into()?,
                    &mut object_count,
                ))
                .into_result()?;
            }
        }

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_FindObjectsFinal)(
                self.handle(),
            ))
            .into_result()?;
        }

        let objects = objects.into_iter().map(ObjectHandle::new).collect();

        Ok(objects)
    }

    /// Create a new object
    pub fn create_object(&self, template: &[Attribute]) -> Result<ObjectHandle> {
        let mut template: Vec<CK_ATTRIBUTE> = template.iter().map(|attr| attr.into()).collect();
        let mut object_handle = 0;

        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_CreateObject)(
                self.handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
                &mut object_handle as CK_OBJECT_HANDLE_PTR,
            ))
            .into_result()?;
        }

        Ok(ObjectHandle::new(object_handle))
    }

    /// Destroy an object
    pub fn destroy_object(&self, object: ObjectHandle) -> Result<()> {
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_DestroyObject)(
                self.handle(),
                object.handle(),
            ))
            .into_result()
        }
    }

    /// Get the attribute info of an object: if the attribute is present and its size.
    pub fn get_attribute_info(
        &self,
        object: ObjectHandle,
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

        match unsafe {
            Rv::from(get_pkcs11!(self.client(), C_GetAttributeValue)(
                self.handle(),
                object.handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
            ))
        } {
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

    /// Get the attributes values of an object.
    /// Ignore the unavailable one. One has to call the get_attribute_info method to check which
    /// ones are unavailable.
    pub fn get_attributes(
        &self,
        object: ObjectHandle,
        attributes: &[AttributeType],
    ) -> Result<Vec<Attribute>> {
        let attrs_info = self.get_attribute_info(object, attributes)?;

        // Allocating a chunk of memory where to put the attributes value.
        let attrs_memory: Vec<(AttributeType, Vec<u8>)> = attrs_info
            .iter()
            .zip(attributes.iter())
            .filter_map(|(attr_info, attr_type)| {
                if let AttributeInfo::Available(size) = attr_info {
                    Some((*attr_type, vec![0; *size]))
                } else {
                    None
                }
            })
            .collect();

        let mut template: Vec<CK_ATTRIBUTE> = attrs_memory
            .iter()
            .map(|(attr_type, memory)| {
                Ok(CK_ATTRIBUTE {
                    type_: (*attr_type).into(),
                    pValue: memory.as_ptr() as *mut std::ffi::c_void,
                    ulValueLen: memory.len().try_into()?,
                })
            })
            .collect::<Result<Vec<CK_ATTRIBUTE>>>()?;

        // This should only return OK as all attributes asked should be
        // available. Concurrency problem?
        unsafe {
            Rv::from(get_pkcs11!(self.client(), C_GetAttributeValue)(
                self.handle(),
                object.handle(),
                template.as_mut_ptr(),
                template.len().try_into()?,
            ))
            .into_result()?;
        }

        // Convert from CK_ATTRIBUTE to Attribute
        template.into_iter().map(|attr| attr.try_into()).collect()
    }
}
