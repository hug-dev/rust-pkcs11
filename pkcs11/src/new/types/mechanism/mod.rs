pub mod rsa;

use crate::new::Error;
use log::error;
use pkcs11_sys::*;
use std::convert::{TryFrom, TryInto};
use std::ffi::c_void;
use std::ops::Deref;
use std::ptr::null_mut;

#[derive(Debug, PartialEq, Eq)]
// transparent so that a vector of MechanismType should have the same layout than a vector of
// CK_MECHANISM_TYPE.
#[repr(transparent)]
pub struct MechanismType {
    val: CK_MECHANISM_TYPE,
}

impl MechanismType {
    // RSA
    pub const RSA_PKCS_KEY_PAIR_GEN: MechanismType = MechanismType {
        val: CKM_RSA_PKCS_KEY_PAIR_GEN,
    };
    pub const RSA_PKCS: MechanismType = MechanismType { val: CKM_RSA_PKCS };
    pub const RSA_PKCS_PSS: MechanismType = MechanismType {
        val: CKM_RSA_PKCS_PSS,
    };
    pub const RSA_PKCS_OAEP: MechanismType = MechanismType {
        val: CKM_RSA_PKCS_OAEP,
    };

    // SHA-n
    pub const SHA1: MechanismType = MechanismType { val: CKM_SHA_1 };
    pub const SHA256: MechanismType = MechanismType { val: CKM_SHA256 };
    pub const SHA384: MechanismType = MechanismType { val: CKM_SHA384 };
    pub const SHA512: MechanismType = MechanismType { val: CKM_SHA512 };
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
            CKM_RSA_PKCS_KEY_PAIR_GEN => Ok(MechanismType::RSA_PKCS_KEY_PAIR_GEN),
            CKM_RSA_PKCS => Ok(MechanismType::RSA_PKCS),
            CKM_RSA_PKCS_PSS => Ok(MechanismType::RSA_PKCS_PSS),
            CKM_RSA_PKCS_OAEP => Ok(MechanismType::RSA_PKCS_OAEP),
            CKM_SHA_1 => Ok(MechanismType::SHA1),
            CKM_SHA256 => Ok(MechanismType::SHA256),
            CKM_SHA384 => Ok(MechanismType::SHA384),
            CKM_SHA512 => Ok(MechanismType::SHA512),
            other => {
                error!("Mechanism type {} is not supported.", other);
                Err(Error::NotSupported)
            }
        }
    }
}

pub enum Mechanism {
    // RSA
    RsaPkcsKeyPairGen,
    RsaPkcs,
    RsaPkcsPss(rsa::PkcsPssParams),
    RsaPkcsOaep(rsa::PkcsOaepParams),

    // SHA-n
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Mechanism {
    pub fn mechanism_type(&self) -> MechanismType {
        match self {
            Mechanism::RsaPkcsKeyPairGen => MechanismType::RSA_PKCS_KEY_PAIR_GEN,
            Mechanism::RsaPkcs => MechanismType::RSA_PKCS,
            Mechanism::RsaPkcsPss(_) => MechanismType::RSA_PKCS_PSS,
            Mechanism::RsaPkcsOaep(_) => MechanismType::RSA_PKCS_OAEP,

            Mechanism::Sha1 => MechanismType::SHA1,
            Mechanism::Sha256 => MechanismType::SHA256,
            Mechanism::Sha384 => MechanismType::SHA384,
            Mechanism::Sha512 => MechanismType::SHA512,
        }
    }
}

impl From<&Mechanism> for CK_MECHANISM {
    fn from(mech: &Mechanism) -> Self {
        let mechanism = mech.mechanism_type().into();
        match mech {
            Mechanism::RsaPkcsPss(params) => CK_MECHANISM {
                mechanism,
                pParameter: params as *const _ as *mut c_void,
                ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>()
                    .try_into()
                    .expect("usize can not fit in CK_ULONG"),
            },
            Mechanism::RsaPkcsOaep(params) => CK_MECHANISM {
                mechanism,
                pParameter: params as *const _ as *mut c_void,
                ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>()
                    .try_into()
                    .expect("usize can not fit in CK_ULONG"),
            },
            // Mechanisms without parameters
            Mechanism::RsaPkcsKeyPairGen
            | Mechanism::RsaPkcs
            | Mechanism::Sha1
            | Mechanism::Sha256
            | Mechanism::Sha384
            | Mechanism::Sha512 => CK_MECHANISM {
                mechanism,
                pParameter: null_mut(),
                ulParameterLen: 0,
            },
        }
    }
}
