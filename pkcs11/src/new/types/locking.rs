use crate::new::types::Flags;
use std::ptr;

pub enum CInitializeArgs {
    NoThreads,
    OsThreads,
    // TODO: add variants for custom mutexes here.
}

impl From<CInitializeArgs> for pkcs11_sys::CK_C_INITIALIZE_ARGS {
    fn from(c_initialize_args: CInitializeArgs) -> Self {
        let mut flags = Flags::default();
        match c_initialize_args {
            CInitializeArgs::NoThreads => {
                flags.set_os_locking_ok(false);
                Self {
                    flags: flags.into(),
                    CreateMutex: None,
                    DestroyMutex: None,
                    LockMutex: None,
                    UnlockMutex: None,
                    pReserved: ptr::null_mut(),
                }
            }
            CInitializeArgs::OsThreads => {
                flags.set_os_locking_ok(true);
                Self {
                    flags: flags.into(),
                    CreateMutex: None,
                    DestroyMutex: None,
                    LockMutex: None,
                    UnlockMutex: None,
                    pReserved: ptr::null_mut(),
                }
            }
        }
    }
}
