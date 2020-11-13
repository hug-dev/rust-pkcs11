use crate::new::types::function::Rv;
use crate::new::types::mechanism::Mechanism;
use crate::new::types::object::{Attribute, Object};
use crate::new::types::session::Session;
use crate::new::Pkcs11;
use crate::new::Result;
use pkcs11_sys::{CK_ATTRIBUTE, CK_MECHANISM, CK_MECHANISM_PTR};
use std::convert::TryInto;
use std::ptr::null_mut;

impl Pkcs11 {
    pub fn generate_key_pair(
        &self,
        session: &Session,
        mechanism: Mechanism,
        pub_key_template: &mut [Attribute],
        priv_key_template: &mut [Attribute],
    ) -> Result<(Object, Object)> {
        let mut mechanism: CK_MECHANISM = mechanism.try_into()?;
        let mut pub_key_template: Vec<CK_ATTRIBUTE> = pub_key_template
            .iter_mut()
            .map(|attr| attr.into())
            .collect();
        let mut priv_key_template: Vec<CK_ATTRIBUTE> = priv_key_template
            .iter_mut()
            .map(|attr| attr.into())
            .collect();
        let mut pub_handle = 0;
        let mut priv_handle = 0;
        Rv::from(unsafe {
            ((*self.function_list).C_GenerateKeyPair.unwrap())(
                session.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                pub_key_template.as_mut_ptr(),
                pub_key_template.len().try_into()?,
                priv_key_template.as_mut_ptr(),
                priv_key_template.len().try_into()?,
                &mut pub_handle,
                &mut priv_handle,
            )
        })
        .to_result()?;

        Ok((Object::new(pub_handle), Object::new(priv_handle)))
    }

    pub fn generate_key(
        &self,
        session: Session,
        mechanism: Mechanism,
        key_template: &mut [Attribute],
    ) -> Result<Object> {
        let mut mechanism: CK_MECHANISM = mechanism.try_into()?;
        let mut key_template: Vec<CK_ATTRIBUTE> =
            key_template.iter_mut().map(|attr| attr.into()).collect();
        let mut handle = 0;
        Rv::from(unsafe {
            ((*self.function_list).C_GenerateKey.unwrap())(
                session.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key_template.as_mut_ptr(),
                key_template.len().try_into()?,
                &mut handle,
            )
        })
        .to_result()?;

        Ok(Object::new(handle))
    }

    pub fn wrap_key(
        &self,
        session: Session,
        mechanism: Mechanism,
        wrapping_key: Object,
        wrapped_key: Object,
    ) -> Result<Vec<u8>> {
        let mut mechanism: CK_MECHANISM = mechanism.try_into()?;
        let wrapped_key_bytes = null_mut();
        let mut wrapped_key_len = 0;
        Rv::from(unsafe {
            ((*self.function_list).C_WrapKey.unwrap())(
                session.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                wrapping_key.handle(),
                wrapped_key.handle(),
                wrapped_key_bytes,
                &mut wrapped_key_len,
            )
        })
        .to_result()?;

        //let len = usize::try_from(wrapped_key_len)
        //.or(Err(Error::InvalidInput("Wrapped key is too long")))?;
        //Ok(unsafe { Vec::from_raw_parts(wrapped_key_bytes, len, len) })

        Ok(Vec::new())
    }

    pub fn unwrap_key(
        &self,
        session: Session,
        mechanism: Mechanism,
        unwrapping_key: Object,
        wrapped_key: &mut [u8],
        wrapped_key_template: &mut [Attribute],
    ) -> Result<Object> {
        let mut mechanism: CK_MECHANISM = mechanism.try_into()?;
        let mut wrapped_key_template: Vec<CK_ATTRIBUTE> = wrapped_key_template
            .iter_mut()
            .map(|attr| attr.into())
            .collect();
        let mut unwrapped_key_handle = 0;
        Rv::from(unsafe {
            ((*self.function_list).C_UnwrapKey.unwrap())(
                session.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                unwrapping_key.handle(),
                wrapped_key.as_mut_ptr(),
                wrapped_key.len().try_into()?,
                wrapped_key_template.as_mut_ptr(),
                wrapped_key_template.len().try_into()?,
                &mut unwrapped_key_handle,
            )
        })
        .to_result()?;

        Ok(Object::new(unwrapped_key_handle))
    }

    pub fn derive_key(
        &self,
        session: Session,
        mechanism: Mechanism,
        base_key: Object,
        derived_key_template: &mut [Attribute],
    ) -> Result<Object> {
        let mut mechanism: CK_MECHANISM = mechanism.try_into()?;
        let mut derived_key_template: Vec<CK_ATTRIBUTE> = derived_key_template
            .iter_mut()
            .map(|attr| attr.into())
            .collect();
        let mut derived_key_handle = 0;
        Rv::from(unsafe {
            ((*self.function_list).C_DeriveKey.unwrap())(
                session.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                base_key.handle(),
                derived_key_template.as_mut_ptr(),
                derived_key_template.len().try_into()?,
                &mut derived_key_handle,
            )
        })
        .to_result()?;

        Ok(Object::new(derived_key_handle))
    }
}
