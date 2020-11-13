use crate::new::types::function::Rv;
use crate::new::types::mechanism::Mechanism;
use crate::new::types::object::Object;
use crate::new::types::session::Session;
use crate::new::Pkcs11;
use crate::new::Result;
use pkcs11_sys::*;
use std::convert::TryInto;

impl Pkcs11 {
    pub fn decrypt(
        &self,
        session: &Session,
        mechanism: Mechanism,
        key: &Object,
        encrypted_data: &mut [u8],
    ) -> Result<Vec<u8>> {
        let mut mechanism: CK_MECHANISM = mechanism.try_into()?;
        let mut data_len = 0;

        Rv::from(unsafe {
            ((*self.function_list).C_DecryptInit.unwrap())(
                session.handle(),
                &mut mechanism as CK_MECHANISM_PTR,
                key.handle(),
            )
        })
        .to_result()?;

        // Get the output buffer length
        Rv::from(unsafe {
            ((*self.function_list).C_Decrypt.unwrap())(
                session.handle(),
                encrypted_data.as_mut_ptr(),
                encrypted_data.len().try_into()?,
                std::ptr::null_mut(),
                &mut data_len,
            )
        })
        .to_result()?;

        let mut data = vec![0; data_len.try_into()?];

        Rv::from(unsafe {
            ((*self.function_list).C_Decrypt.unwrap())(
                session.handle(),
                encrypted_data.as_mut_ptr(),
                encrypted_data.len().try_into()?,
                data.as_mut_ptr(),
                &mut data_len,
            )
        })
        .to_result()?;

        data.resize(data_len.try_into()?, 0);

        Ok(data)
    }
}
