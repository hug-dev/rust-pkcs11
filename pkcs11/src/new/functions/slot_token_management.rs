//! Slot and token management functions

use crate::get_pkcs11;
use crate::new::types::function::Rv;
use crate::new::types::slot_token::Slot;
use crate::new::Pkcs11;
use crate::new::Result;
use std::convert::TryInto;

impl Pkcs11 {
    /// Get all slots available with a token
    pub fn get_slots_with_token(&self) -> Result<Vec<Slot>> {
        let mut slot_count = 0;

        unsafe {
            Rv::from(get_pkcs11!(self, C_GetSlotList)(
                pkcs11_sys::CK_TRUE,
                std::ptr::null_mut(),
                &mut slot_count,
            ))
            .into_result()?;
        }

        let mut slots = vec![0; slot_count.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self, C_GetSlotList)(
                pkcs11_sys::CK_TRUE,
                slots.as_mut_ptr(),
                &mut slot_count,
            ))
            .into_result()?;
        }

        let mut slots: Vec<Slot> = slots.into_iter().map(Slot::new).collect();

        // This should always truncate slots.
        slots.resize(slot_count.try_into()?, Slot::new(0));

        Ok(slots)
    }

    /// Get all slots
    pub fn get_all_slots(&self) -> Result<Vec<Slot>> {
        let mut slot_count = 0;

        unsafe {
            Rv::from(get_pkcs11!(self, C_GetSlotList)(
                pkcs11_sys::CK_FALSE,
                std::ptr::null_mut(),
                &mut slot_count,
            ))
            .into_result()?;
        }

        let mut slots = vec![0; slot_count.try_into()?];

        unsafe {
            Rv::from(get_pkcs11!(self, C_GetSlotList)(
                pkcs11_sys::CK_FALSE,
                slots.as_mut_ptr(),
                &mut slot_count,
            ))
            .into_result()?;
        }

        let mut slots: Vec<Slot> = slots.into_iter().map(Slot::new).collect();

        // This should always truncate slots.
        slots.resize(slot_count.try_into()?, Slot::new(0));

        Ok(slots)
    }
}
