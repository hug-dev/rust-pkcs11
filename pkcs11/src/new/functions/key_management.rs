use crate::errors::Error;
use crate::new::types::mechanism::Mechanism;
use crate::new::types::object::{Attribute, Object};
use crate::new::types::session::Session;
use crate::new::Pkcs11;
use pkcs11_sys::{CKR_OK, CK_ATTRIBUTE, CK_MECHANISM, CK_MECHANISM_PTR, CK_ULONG};
use std::convert::{TryFrom, TryInto};
use std::ptr::null_mut;

impl Pkcs11 {
    pub fn generate_key_pair(
        &self,
        session: &Session,
        mechanism: Mechanism,
        pub_key_template: &mut [Attribute],
        priv_key_template: &mut [Attribute],
    ) -> Result<(Object, Object), Error> {
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
        match unsafe {
            ((*self.function_list).C_GenerateKeyPair.unwrap())(
                session.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                pub_key_template.as_mut_ptr(),
                pub_key_template.len() as CK_ULONG,
                priv_key_template.as_mut_ptr(),
                priv_key_template.len() as CK_ULONG,
                &mut pub_handle,
                &mut priv_handle,
            )
        } {
            CKR_OK => Ok((Object::new(pub_handle)?, Object::new(priv_handle)?)),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn generate_key(
        &self,
        session: Session,
        mechanism: Mechanism,
        key_template: &mut [Attribute],
    ) -> Result<Object, Error> {
        let mut mechanism: CK_MECHANISM = mechanism.try_into()?;
        let mut key_template: Vec<CK_ATTRIBUTE> =
            key_template.iter_mut().map(|attr| attr.into()).collect();
        let mut handle = 0;
        match unsafe {
            ((*self.function_list).C_GenerateKey.unwrap())(
                session.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key_template.as_mut_ptr(),
                key_template.len() as CK_ULONG,
                &mut handle,
            )
        } {
            CKR_OK => Ok(Object::new(handle)?),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn wrap_key(
        &self,
        session: Session,
        mechanism: Mechanism,
        wrapping_key: Object,
        wrapped_key: Object,
    ) -> Result<Vec<u8>, Error> {
        let mut mechanism: CK_MECHANISM = mechanism.try_into()?;
        let wrapped_key_bytes = null_mut();
        let mut wrapped_key_len = 0;
        match unsafe {
            ((*self.function_list).C_WrapKey.unwrap())(
                session.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                wrapping_key.handle(),
                wrapped_key.handle(),
                wrapped_key_bytes,
                &mut wrapped_key_len,
            )
        } {
            CKR_OK => {
                let len = usize::try_from(wrapped_key_len)
                    .or(Err(Error::InvalidInput("Wrapped key is too long")))?;
                Ok(unsafe { Vec::from_raw_parts(wrapped_key_bytes, len, len) })
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn unwrap_key(
        &self,
        session: Session,
        mechanism: Mechanism,
        unwrapping_key: Object,
        wrapped_key: &mut [u8],
        wrapped_key_template: &mut [Attribute],
    ) -> Result<Object, Error> {
        let mut mechanism: CK_MECHANISM = mechanism.try_into()?;
        let mut wrapped_key_template: Vec<CK_ATTRIBUTE> = wrapped_key_template
            .iter_mut()
            .map(|attr| attr.into())
            .collect();
        let mut unwrapped_key_handle = 0;
        match unsafe {
            ((*self.function_list).C_UnwrapKey.unwrap())(
                session.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                unwrapping_key.handle(),
                wrapped_key.as_mut_ptr(),
                u64::try_from(wrapped_key.len())
                    .or(Err(Error::InvalidInput("Wrapped key is too long")))?,
                wrapped_key_template.as_mut_ptr(),
                u64::try_from(wrapped_key_template.len())
                    .or(Err(Error::InvalidInput("Wrapped key template is too long")))?,
                &mut unwrapped_key_handle,
            )
        } {
            CKR_OK => Ok(Object::new(unwrapped_key_handle)?),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn derive_key(
        &self,
        session: Session,
        mechanism: Mechanism,
        base_key: Object,
        derived_key_template: &mut [Attribute],
    ) -> Result<Object, Error> {
        let mut mechanism: CK_MECHANISM = mechanism.try_into()?;
        let mut derived_key_template: Vec<CK_ATTRIBUTE> = derived_key_template
            .iter_mut()
            .map(|attr| attr.into())
            .collect();
        let mut derived_key_handle = 0;
        match unsafe {
            ((*self.function_list).C_DeriveKey.unwrap())(
                session.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                base_key.handle(),
                derived_key_template.as_mut_ptr(),
                u64::try_from(derived_key_template.len())
                    .or(Err(Error::InvalidInput("Derived key template is too long")))?,
                &mut derived_key_handle,
            )
        } {
            CKR_OK => Ok(Object::new(derived_key_handle)?),
            err => Err(Error::Pkcs11(err)),
        }
    }
}
