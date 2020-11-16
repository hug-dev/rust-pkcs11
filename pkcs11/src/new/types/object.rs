use pkcs11_sys::*;
use std::convert::TryInto;

#[derive(Debug, Copy, Clone)]
pub enum AttributeType {
    Base,
    Class,
    Copyable,
    Decrypt,
    Derive,
    Encrypt,
    Extractable,
    KeyType,
    Label,
    Modifiable,
    ModulusBits,
    Modulus,
    Prime,
    Private,
    PublicExponent,
    Sensitive,
    Sign,
    SignRecover,
    Token,
    Unwrap,
    Value,
    ValueLen,
    Verify,
    VerifyRecover,
    Wrap,
}

impl From<AttributeType> for CK_ATTRIBUTE_TYPE {
    fn from(attribute_type: AttributeType) -> Self {
        match attribute_type {
            AttributeType::Base => CKA_BASE,
            AttributeType::Class => CKA_CLASS,
            AttributeType::Copyable => CKA_COPYABLE,
            AttributeType::Decrypt => CKA_DECRYPT,
            AttributeType::Derive => CKA_DERIVE,
            AttributeType::Encrypt => CKA_ENCRYPT,
            AttributeType::Extractable => CKA_EXTRACTABLE,
            AttributeType::KeyType => CKA_KEY_TYPE,
            AttributeType::Label => CKA_LABEL,
            AttributeType::Modifiable => CKA_MODIFIABLE,
            AttributeType::ModulusBits => CKA_MODULUS_BITS,
            AttributeType::Modulus => CKA_MODULUS,
            AttributeType::Prime => CKA_PRIME,
            AttributeType::Private => CKA_PRIVATE,
            AttributeType::PublicExponent => CKA_PUBLIC_EXPONENT,
            AttributeType::Sensitive => CKA_SENSITIVE,
            AttributeType::Sign => CKA_SIGN,
            AttributeType::SignRecover => CKA_SIGN_RECOVER,
            AttributeType::Token => CKA_TOKEN,
            AttributeType::Unwrap => CKA_UNWRAP,
            AttributeType::Value => CKA_VALUE,
            AttributeType::ValueLen => CKA_VALUE_LEN,
            AttributeType::Verify => CKA_VERIFY,
            AttributeType::VerifyRecover => CKA_VERIFY_RECOVER,
            AttributeType::Wrap => CKA_WRAP,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Attribute<'a> {
    Base(&'a mut CK_BYTE),
    Class(&'a mut CK_OBJECT_CLASS),
    Copyable(&'a mut CK_BBOOL),
    Decrypt(&'a mut CK_BBOOL),
    Derive(&'a mut CK_BBOOL),
    Encrypt(&'a mut CK_BBOOL),
    Extractable(&'a mut CK_BBOOL),
    KeyType(&'a mut CK_KEY_TYPE),
    Label(&'a mut [CK_UTF8CHAR]),
    Modifiable(&'a mut CK_BBOOL),
    ModulusBits(&'a mut CK_ULONG),
    Modulus(&'a mut [CK_BYTE]),
    Prime(&'a mut [CK_BYTE]),
    Private(&'a mut CK_BBOOL),
    PublicExponent(&'a mut [CK_BYTE]),
    Sensitive(&'a mut CK_BBOOL),
    Sign(&'a mut CK_BBOOL),
    SignRecover(&'a mut CK_BBOOL),
    Token(&'a mut CK_BBOOL),
    Unwrap(&'a mut CK_BBOOL),
    Value(&'a mut [u8]),
    ValueLen(&'a mut CK_ULONG),
    Verify(&'a mut CK_BBOOL),
    VerifyRecover(&'a mut CK_BBOOL),
    Wrap(&'a mut CK_BBOOL),
}

impl Attribute<'_> {
    pub fn attribute_type(&self) -> AttributeType {
        match self {
            Attribute::Base(_) => AttributeType::Base,
            Attribute::Class(_) => AttributeType::Class,
            Attribute::Copyable(_) => AttributeType::Copyable,
            Attribute::Decrypt(_) => AttributeType::Decrypt,
            Attribute::Derive(_) => AttributeType::Derive,
            Attribute::Encrypt(_) => AttributeType::Encrypt,
            Attribute::Extractable(_) => AttributeType::Extractable,
            Attribute::KeyType(_) => AttributeType::KeyType,
            Attribute::Label(_) => AttributeType::Label,
            Attribute::Modifiable(_) => AttributeType::Modifiable,
            Attribute::ModulusBits(_) => AttributeType::ModulusBits,
            Attribute::Modulus(_) => AttributeType::Modulus,
            Attribute::Prime(_) => AttributeType::Prime,
            Attribute::Private(_) => AttributeType::Private,
            Attribute::PublicExponent(_) => AttributeType::PublicExponent,
            Attribute::Sensitive(_) => AttributeType::Sensitive,
            Attribute::Sign(_) => AttributeType::Sign,
            Attribute::SignRecover(_) => AttributeType::SignRecover,
            Attribute::Token(_) => AttributeType::Token,
            Attribute::Unwrap(_) => AttributeType::Unwrap,
            Attribute::Value(_) => AttributeType::Value,
            Attribute::ValueLen(_) => AttributeType::ValueLen,
            Attribute::Verify(_) => AttributeType::Verify,
            Attribute::VerifyRecover(_) => AttributeType::VerifyRecover,
            Attribute::Wrap(_) => AttributeType::Wrap,
        }
    }

    /// Returns the length in bytes of the objects contained by this CkAttribute.
    fn len(&self) -> CK_ULONG {
        let len = match self {
            Attribute::Copyable(_)
            | Attribute::Decrypt(_)
            | Attribute::Derive(_)
            | Attribute::Encrypt(_)
            | Attribute::Extractable(_)
            | Attribute::Modifiable(_)
            | Attribute::Private(_)
            | Attribute::Sensitive(_)
            | Attribute::Sign(_)
            | Attribute::SignRecover(_)
            | Attribute::Token(_)
            | Attribute::Unwrap(_)
            | Attribute::Verify(_)
            | Attribute::VerifyRecover(_)
            | Attribute::Wrap(_) => std::mem::size_of::<CK_BBOOL>(),
            Attribute::Base(_) => std::mem::size_of::<CK_BYTE>(),
            Attribute::Class(_) => std::mem::size_of::<CK_OBJECT_CLASS>(),
            Attribute::KeyType(_) => std::mem::size_of::<CK_KEY_TYPE>(),
            Attribute::Label(label) => std::mem::size_of::<CK_UTF8CHAR>() * label.len(),
            Attribute::ModulusBits(_) => std::mem::size_of::<CK_ULONG>(),
            Attribute::Prime(bytes) => std::mem::size_of::<CK_BYTE>() * bytes.len(),
            Attribute::PublicExponent(bytes) => std::mem::size_of::<CK_BYTE>() * bytes.len(),
            Attribute::Modulus(bytes) => std::mem::size_of::<CK_BYTE>() * bytes.len(),
            Attribute::Value(bytes) => std::mem::size_of::<u8>() * bytes.len(),
            Attribute::ValueLen(_) => std::mem::size_of::<CK_ULONG>(),
        };
        len.try_into().unwrap()
    }

    /// Returns a CK_VOID_PTR pointing to the object contained by this CkAttribute.
    fn ptr(&mut self) -> CK_VOID_PTR {
        match self {
            Attribute::Copyable(b)
            | Attribute::Decrypt(b)
            | Attribute::Derive(b)
            | Attribute::Encrypt(b)
            | Attribute::Extractable(b)
            | Attribute::Modifiable(b)
            | Attribute::Private(b)
            | Attribute::Sensitive(b)
            | Attribute::Sign(b)
            | Attribute::SignRecover(b)
            | Attribute::Token(b)
            | Attribute::Unwrap(b)
            | Attribute::Verify(b)
            | Attribute::VerifyRecover(b)
            | Attribute::Wrap(b) => *b as *mut _ as CK_VOID_PTR,
            Attribute::Base(byte) => *byte as *mut _ as CK_VOID_PTR,
            Attribute::Class(object_class) => *object_class as CK_OBJECT_CLASS_PTR as CK_VOID_PTR,
            Attribute::KeyType(key_type) => *key_type as *mut _ as CK_VOID_PTR,
            Attribute::Label(label) => label.as_ptr() as CK_VOID_PTR,
            Attribute::ModulusBits(bits) => *bits as *mut _ as CK_VOID_PTR,
            Attribute::Prime(bytes) => bytes.as_ptr() as CK_VOID_PTR,
            Attribute::PublicExponent(bytes) => bytes.as_ptr() as CK_VOID_PTR,
            Attribute::Modulus(bytes) => bytes.as_ptr() as CK_VOID_PTR,
            Attribute::Value(value) => value.as_ptr() as CK_VOID_PTR,
            Attribute::ValueLen(len) => *len as *mut _ as CK_VOID_PTR,
        }
    }
}

impl From<&mut Attribute<'_>> for CK_ATTRIBUTE {
    fn from(attribute: &mut Attribute) -> Self {
        Self {
            type_: attribute.attribute_type().into(),
            pValue: attribute.ptr(),
            ulValueLen: attribute.len(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ObjectHandle {
    handle: CK_OBJECT_HANDLE,
}

impl ObjectHandle {
    pub(crate) fn new(handle: CK_OBJECT_HANDLE) -> Self {
        ObjectHandle { handle }
    }

    pub(crate) fn handle(&self) -> CK_OBJECT_HANDLE {
        self.handle
    }
}

#[derive(Debug, Copy, Clone)]
pub enum AttributeInfo {
    Unavailable,
    Available(usize),
}
