use crate::get_pkcs11;
use crate::new::types::function::Rv;
use crate::new::types::mechanism::Mechanism;
use crate::new::types::object::ObjectHandle;
use crate::new::types::session::Session;
use crate::new::Pkcs11;
use crate::new::Result;
use pkcs11_sys::*;
use std::convert::TryInto;

impl Pkcs11 {
    pub fn sign(
        &self,
        session: &Session,
        mechanism: Mechanism,
        key: ObjectHandle,
        data: &mut [u8],
    ) -> Result<Vec<u8>> {
        let mut mechanism: CK_MECHANISM = mechanism.try_into()?;
        let mut signature_len = 0;

        unsafe {
            Rv::from(get_pkcs11!(self, C_SignInit)(
                session.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key.handle(),
            ))
            .into_result()?;
        }

        // Get the output buffer length
        unsafe {
            Rv::from(get_pkcs11!(self, C_Sign)(
                session.handle(),
                data.as_mut_ptr(),
                data.len().try_into()?,
                std::ptr::null_mut(),
                &mut signature_len,
            ))
            .into_result()?;
        }

        let mut signature = vec![0; signature_len.try_into()?];

        //TODO: we should add a new error instead of those unwrap!
        unsafe {
            Rv::from(get_pkcs11!(self, C_Sign)(
                session.handle(),
                data.as_mut_ptr(),
                data.len().try_into()?,
                signature.as_mut_ptr(),
                &mut signature_len,
            ))
            .into_result()?;
        }

        signature.resize(signature_len.try_into()?, 0);

        Ok(signature)
    }

    pub fn verify(
        &self,
        session: &Session,
        mechanism: Mechanism,
        key: ObjectHandle,
        data: &mut [u8],
        signature: &mut [u8],
    ) -> Result<()> {
        let mut mechanism: CK_MECHANISM = mechanism.try_into()?;

        unsafe {
            Rv::from(get_pkcs11!(self, C_VerifyInit)(
                session.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key.handle(),
            ))
            .into_result()?;
        }

        unsafe {
            Rv::from(get_pkcs11!(self, C_Verify)(
                session.handle(),
                data.as_mut_ptr(),
                data.len().try_into()?,
                signature.as_mut_ptr(),
                signature.len().try_into()?,
            ))
            .into_result()
        }
    }
}
