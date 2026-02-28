use std::panic::{catch_unwind, AssertUnwindSafe};

use thiserror::Error;

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum lib_error {
    #[error("LIB_OK")]
    LIB_OK,

    #[error("Invalid Handle")]
    LIB_INVALID_HANDLE,

    #[error("Handle in use")]
    LIB_HANDLE_IN_USE,

    #[error("Invalid handle type")]
    LIB_INVALID_HANDLE_TYPE,

    #[error("Null pointer")]
    LIB_NULL_PTR,

    #[error("Invalid buffer size")]
    LIB_INVALID_BUFFER_SIZE,

    #[error("Unknown error")]
    LIB_UNKNOWN_ERROR,

    #[error("Serialization error")]
    LIB_SERIALIZATION_ERROR,

    #[error("Invalid identifier")]
    LIB_INVALID_IDENTIFIER,

    #[error("DKG error")]
    LIB_DKG_ERROR,

    #[error("Signing error")]
    LIB_SIGNING_ERROR,

    #[error("Reshare error")]
    LIB_RESHARE_ERROR,

    #[error("Key import error")]
    LIB_KEY_IMPORT_ERROR,

    #[error("Sapling error")]
    LIB_SAPLING_ERROR,
}

impl From<crate::handle::Error> for lib_error {
    fn from(value: crate::handle::Error) -> Self {
        match value {
            crate::handle::Error::NullHandle => lib_error::LIB_INVALID_HANDLE,
            crate::handle::Error::NotFound => lib_error::LIB_INVALID_HANDLE,
            crate::handle::Error::InUse => lib_error::LIB_HANDLE_IN_USE,
            crate::handle::Error::InvalidType => lib_error::LIB_INVALID_HANDLE_TYPE,
            crate::handle::Error::TableFull => lib_error::LIB_UNKNOWN_ERROR,
        }
    }
}

impl From<crate::bytes::Error> for lib_error {
    fn from(value: crate::bytes::Error) -> Self {
        match value {
            crate::bytes::Error::NullPtr => lib_error::LIB_NULL_PTR,
            crate::bytes::Error::InvalidSize => lib_error::LIB_INVALID_BUFFER_SIZE,
        }
    }
}

pub(crate) fn with_error_handler<F>(f: F) -> lib_error
where
    F: FnOnce() -> Result<(), lib_error>,
{
    catch_unwind(AssertUnwindSafe(|| match f() {
        Ok(_) => lib_error::LIB_OK,
        Err(e) => e,
    }))
    .unwrap_or(lib_error::LIB_UNKNOWN_ERROR)
}
