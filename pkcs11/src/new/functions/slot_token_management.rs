use crate::new::types::function::Rv;
use crate::new::types::slot_token::Slot;
use crate::new::Pkcs11;
use crate::new::Result;
use std::convert::TryInto;

impl Pkcs11 {
    pub fn get_slots_with_token(&self) -> Result<Vec<Slot>> {
        let mut slot_count = 0;

        Rv::from(unsafe {
            ((*self.function_list).C_GetSlotList.unwrap())(
                pkcs11_sys::CK_TRUE,
                std::ptr::null_mut(),
                &mut slot_count,
            )
        })
        .to_result()?;

        let mut slots = vec![0; slot_count.try_into()?];

        Rv::from(unsafe {
            ((*self.function_list).C_GetSlotList.unwrap())(
                pkcs11_sys::CK_TRUE,
                slots.as_mut_ptr(),
                &mut slot_count,
            )
        })
        .to_result()?;

        let mut slots: Vec<Slot> = slots.into_iter().map(|e| Slot::new(e)).collect();

        // This should always truncate slots.
        slots.resize(slot_count.try_into()?, Slot::new(0));

        Ok(slots)
    }

    pub fn get_all_slots(&self) -> Result<Vec<Slot>> {
        let mut slot_count = 0;

        Rv::from(unsafe {
            ((*self.function_list).C_GetSlotList.unwrap())(
                pkcs11_sys::CK_FALSE,
                std::ptr::null_mut(),
                &mut slot_count,
            )
        })
        .to_result()?;

        let mut slots = vec![0; slot_count.try_into()?];

        Rv::from(unsafe {
            ((*self.function_list).C_GetSlotList.unwrap())(
                pkcs11_sys::CK_FALSE,
                slots.as_mut_ptr(),
                &mut slot_count,
            )
        })
        .to_result()?;

        let mut slots: Vec<Slot> = slots.into_iter().map(|e| Slot::new(e)).collect();

        // This should always truncate slots.
        slots.resize(slot_count.try_into()?, Slot::new(0));

        Ok(slots)
    }
}
