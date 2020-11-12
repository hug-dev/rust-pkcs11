use crate::new::{Error, Result};
use pkcs11_sys::*;

#[derive(Debug)]
pub enum Rv {
    Ok,
    Error(RvError),
}

impl From<CK_RV> for Rv {
    fn from(ck_rv: CK_RV) -> Self {
        match ck_rv {
            CKR_OK => Rv::Ok,
            _err => Rv::Error(RvError::GeneralError),
        }
    }
}

#[derive(Debug)]
pub enum RvError {
    GeneralError,
    CryptokiNotInitialised,
    CryptokiAlreadyInitialised,
}

impl From<RvError> for Error {
    fn from(rv_error: RvError) -> Self {
        Error::Pkcs11(rv_error)
    }
}

impl Rv {
    pub fn to_result(self) -> Result<()> {
        match self {
            Rv::Ok => Ok(()),
            Rv::Error(rv_error) => Err(Error::Pkcs11(rv_error)),
        }
    }
}
