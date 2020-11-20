mod rsa;

use crate::new::Error;
use log::error;
use pkcs11_sys::*;
use std::convert::TryFrom;
use std::ops::Deref;
use std::ptr::null_mut;

const RSA_PKCS_KEY_PAIR_GEN: MechanismType = MechanismType {
    val: CKM_RSA_PKCS_KEY_PAIR_GEN,
};
const RSA_PKCS: MechanismType = MechanismType { val: CKM_RSA_PKCS };

#[derive(Debug, PartialEq, Eq)]
// transparent so that a vector of MechanismType should have the same layout than a vector of
// CK_MECHANISM_TYPE.
#[repr(transparent)]
pub struct MechanismType {
    val: CK_MECHANISM_TYPE,
}

impl Deref for MechanismType {
    type Target = CK_MECHANISM_TYPE;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl From<MechanismType> for CK_MECHANISM_TYPE {
    fn from(mechanism_type: MechanismType) -> Self {
        *mechanism_type
    }
}

impl TryFrom<CK_MECHANISM_TYPE> for MechanismType {
    type Error = Error;

    fn try_from(mechanism_type: CK_MECHANISM_TYPE) -> Result<Self, Self::Error> {
        match mechanism_type {
            CKM_RSA_PKCS_KEY_PAIR_GEN => Ok(RSA_PKCS_KEY_PAIR_GEN),
            other => {
                error!("Mechanism type {} is not supported.", other);
                Err(Error::NotSupported)
            }
        }
    }
}

pub enum Mechanism {
    RsaPkcsKeyPairGen,
    RsaPkcs,
}

impl Mechanism {
    pub fn mechanism_type(&self) -> MechanismType {
        match self {
            Mechanism::RsaPkcsKeyPairGen => RSA_PKCS_KEY_PAIR_GEN,
            Mechanism::RsaPkcs => RSA_PKCS,
        }
    }
}

impl From<&Mechanism> for CK_MECHANISM {
    fn from(mech: &Mechanism) -> Self {
        let mechanism = mech.mechanism_type().into();
        match mech {
            Mechanism::RsaPkcsKeyPairGen | Mechanism::RsaPkcs => CK_MECHANISM {
                mechanism,
                pParameter: null_mut(),
                ulParameterLen: 0,
            },
        }
    }
}
