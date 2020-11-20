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
    pub fn decrypt(
        &self,
        session: &Session,
        mechanism: &Mechanism,
        key: ObjectHandle,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut mechanism: CK_MECHANISM = mechanism.into();
        let mut data_len = 0;

        unsafe {
            Rv::from(get_pkcs11!(self, C_DecryptInit)(
                session.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key.handle(),
            ))
            .into_result()?;
        }

        // Get the output buffer length
        unsafe {
            Rv::from(get_pkcs11!(self, C_Decrypt)(
                session.handle(),
                // C_Decrypt should not modify this buffer
                encrypted_data.as_ptr() as *mut u8,
                encrypted_data.len().try_into()?,
                std::ptr::null_mut(),
                &mut data_len,
            ))
            .into_result()?;
        }

        let mut data = vec![0; data_len.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self, C_Decrypt)(
                session.handle(),
                encrypted_data.as_ptr() as *mut u8,
                encrypted_data.len().try_into()?,
                data.as_mut_ptr(),
                &mut data_len,
            ))
            .into_result()?;
        }

        data.resize(data_len.try_into()?, 0);

        Ok(data)
    }
}
