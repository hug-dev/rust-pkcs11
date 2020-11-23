use crate::new::types::mechanism::{Mechanism, MechanismType};
use crate::new::types::Ulong;
use crate::new::{Error, Result};
use log::error;
use pkcs11_sys::*;
use std::convert::TryFrom;
use std::ffi::c_void;
use std::ops::Deref;

#[derive(Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct PkcsMgfType {
    val: CK_RSA_PKCS_MGF_TYPE,
}

impl PkcsMgfType {
    pub const MGF1_SHA1: PkcsMgfType = PkcsMgfType { val: CKG_MGF1_SHA1 };
    pub const MGF1_SHA224: PkcsMgfType = PkcsMgfType {
        val: CKG_MGF1_SHA224,
    };
    pub const MGF1_SHA256: PkcsMgfType = PkcsMgfType {
        val: CKG_MGF1_SHA256,
    };
    pub const MGF1_SHA384: PkcsMgfType = PkcsMgfType {
        val: CKG_MGF1_SHA384,
    };
    pub const MGF1_SHA512: PkcsMgfType = PkcsMgfType {
        val: CKG_MGF1_SHA512,
    };
}

impl Deref for PkcsMgfType {
    type Target = CK_RSA_PKCS_MGF_TYPE;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl From<PkcsMgfType> for CK_RSA_PKCS_MGF_TYPE {
    fn from(mgf_type: PkcsMgfType) -> Self {
        *mgf_type
    }
}

impl TryFrom<CK_RSA_PKCS_MGF_TYPE> for PkcsMgfType {
    type Error = Error;

    fn try_from(mgf_type: CK_RSA_PKCS_MGF_TYPE) -> Result<Self> {
        match mgf_type {
            CKG_MGF1_SHA1 => Ok(PkcsMgfType::MGF1_SHA1),
            CKG_MGF1_SHA224 => Ok(PkcsMgfType::MGF1_SHA224),
            CKG_MGF1_SHA256 => Ok(PkcsMgfType::MGF1_SHA256),
            CKG_MGF1_SHA384 => Ok(PkcsMgfType::MGF1_SHA384),
            CKG_MGF1_SHA512 => Ok(PkcsMgfType::MGF1_SHA512),
            other => {
                error!(
                    "Mask Generation Function type {} is not one of the valid values.",
                    other
                );
                Err(Error::InvalidValue)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct PkcsOaepSourceType {
    val: CK_RSA_PKCS_OAEP_SOURCE_TYPE,
}

impl PkcsOaepSourceType {
    pub const DATA_SPECIFIED: PkcsOaepSourceType = PkcsOaepSourceType {
        val: CKZ_DATA_SPECIFIED,
    };
}

impl Deref for PkcsOaepSourceType {
    type Target = CK_RSA_PKCS_OAEP_SOURCE_TYPE;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl From<PkcsOaepSourceType> for CK_RSA_PKCS_OAEP_SOURCE_TYPE {
    fn from(pkcs_oaep_source_type: PkcsOaepSourceType) -> Self {
        *pkcs_oaep_source_type
    }
}

impl TryFrom<CK_RSA_PKCS_OAEP_SOURCE_TYPE> for PkcsOaepSourceType {
    type Error = Error;

    fn try_from(pkcs_oaep_source_type: CK_RSA_PKCS_OAEP_SOURCE_TYPE) -> Result<Self> {
        match pkcs_oaep_source_type {
            CKZ_DATA_SPECIFIED => Ok(PkcsOaepSourceType::DATA_SPECIFIED),
            other => {
                error!("OAEP source type {} is not one of the valid values.", other);
                Err(Error::InvalidValue)
            }
        }
    }
}

/// Abstraction over CK_RSA_PKCS_PSS_PARAMS, share the same memory representation.
#[repr(C)]
pub struct PkcsPssParams {
    pub hash_alg: MechanismType,
    pub mgf: PkcsMgfType,
    pub s_len: Ulong,
}

impl From<PkcsPssParams> for Mechanism {
    fn from(pkcs_pss_params: PkcsPssParams) -> Self {
        Mechanism::RsaPkcsPss(pkcs_pss_params)
    }
}

/// Abstraction over CK_RSA_PKCS_OAEP_PARAMS, share the same memory representation.
#[repr(C)]
pub struct PkcsOaepParams {
    pub hash_alg: MechanismType,
    pub mgf: PkcsMgfType,
    pub source: PkcsOaepSourceType,
    pub source_data: c_void,
    pub source_data_len: Ulong,
}

impl From<PkcsOaepParams> for Mechanism {
    fn from(pkcs_oaep_params: PkcsOaepParams) -> Self {
        Mechanism::RsaPkcsOaep(pkcs_oaep_params)
    }
}
