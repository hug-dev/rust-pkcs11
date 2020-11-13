use crate::get_pkcs11;
use crate::new::types::function::Rv;
use crate::new::types::mechanism::Mechanism;
use crate::new::types::object::Object;
use crate::new::types::session::Session;
use crate::new::Pkcs11;
use crate::new::Result;
use pkcs11_sys::*;
use std::convert::TryInto;

impl Pkcs11 {
    pub fn encrypt(
        &self,
        session: &Session,
        mechanism: Mechanism,
        key: &Object,
        data: &mut [u8],
    ) -> Result<Vec<u8>> {
        let mut mechanism: CK_MECHANISM = mechanism.try_into()?;
        let mut encrypted_data_len = 0;

        unsafe {
            Rv::from(get_pkcs11!(self, C_EncryptInit)(
                session.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key.handle(),
            ))
            .into_result()?;
        }

        // Get the output buffer length
        unsafe {
            Rv::from(get_pkcs11!(self, C_Encrypt)(
                session.handle(),
                data.as_mut_ptr(),
                data.len().try_into()?,
                std::ptr::null_mut(),
                &mut encrypted_data_len,
            ))
            .into_result()?;
        }

        let mut encrypted_data = vec![0; encrypted_data_len.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self, C_Encrypt)(
                session.handle(),
                data.as_mut_ptr(),
                data.len().try_into()?,
                encrypted_data.as_mut_ptr(),
                &mut encrypted_data_len,
            ))
            .into_result()?;
        }

        encrypted_data.resize(encrypted_data_len.try_into()?, 0);

        Ok(encrypted_data)
    }
}
