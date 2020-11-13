use crate::new::types::function::Rv;
use crate::new::types::mechanism::Mechanism;
use crate::new::types::object::{Attribute, Object};
use crate::new::types::session::Session;
use crate::new::Pkcs11;
use crate::new::{Error, Result};
use pkcs11_sys::{CK_ATTRIBUTE, CK_MECHANISM, CK_MECHANISM_PTR};
use std::convert::TryInto;

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
        _session: Session,
        _mechanism: Mechanism,
        _wrapping_key: Object,
        _wrapped_key: Object,
    ) -> Result<Vec<u8>> {
        Err(Error::NotSupported)
    }

    pub fn unwrap_key(
        &self,
        _session: Session,
        _mechanism: Mechanism,
        _unwrapping_key: Object,
        _wrapped_key: &mut [u8],
        _wrapped_key_template: &mut [Attribute],
    ) -> Result<Object> {
        Err(Error::NotSupported)
    }

    pub fn derive_key(
        &self,
        _session: Session,
        _mechanism: Mechanism,
        _base_key: Object,
        _derived_key_template: &mut [Attribute],
    ) -> Result<Object> {
        Err(Error::NotSupported)
    }
}
