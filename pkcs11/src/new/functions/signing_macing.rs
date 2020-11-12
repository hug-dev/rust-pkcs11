use crate::new::types::function::Rv;
use crate::new::types::mechanism::Mechanism;
use crate::new::types::object::Object;
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
        key: &Object,
        data: &mut [u8],
    ) -> Result<Vec<u8>> {
        let mut mechanism: CK_MECHANISM = mechanism.try_into()?;
        let mut signature_len = 0;

        Rv::from(unsafe {
            ((*self.function_list).C_SignInit.unwrap())(
                session.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key.handle(),
            )
        })
        .to_result()?;

        // Get the output buffer length
        Rv::from(unsafe {
            ((*self.function_list).C_Sign.unwrap())(
                session.handle(),
                data.as_mut_ptr(),
                data.len().try_into()?,
                std::ptr::null_mut(),
                &mut signature_len,
            )
        })
        .to_result()?;

        let mut signature = vec![0; signature_len.try_into()?];

        //TODO: we should add a new error instead of those unwrap!
        Rv::from(unsafe {
            ((*self.function_list).C_Sign.unwrap())(
                session.handle(),
                data.as_mut_ptr(),
                data.len().try_into()?,
                signature.as_mut_ptr(),
                &mut signature_len,
            )
        })
        .to_result()?;

        Ok(signature)
    }

    pub fn verify(
        &self,
        session: &Session,
        mechanism: Mechanism,
        key: &Object,
        data: &mut [u8],
        signature: &mut [u8],
    ) -> Result<()> {
        let mut mechanism: CK_MECHANISM = mechanism.try_into()?;

        Rv::from(unsafe {
            ((*self.function_list).C_VerifyInit.unwrap())(
                session.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key.handle(),
            )
        })
        .to_result()?;

        Rv::from(unsafe {
            ((*self.function_list).C_Verify.unwrap())(
                session.handle(),
                data.as_mut_ptr(),
                data.len().try_into()?,
                signature.as_mut_ptr(),
                signature.len().try_into()?,
            )
        })
        .to_result()
    }
}
