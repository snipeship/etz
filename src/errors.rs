use anyhow::Error;
use thiserror::Error;

pub const EXIT_OK: i32 = 0;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_NOT_INITIALIZED: i32 = 10;
pub const EXIT_NOT_FOUND: i32 = 11;
pub const EXIT_VALIDATION: i32 = 12;
pub const EXIT_GIT: i32 = 20;
pub const EXIT_CHECK_FAILED: i32 = 30;
pub const EXIT_INTERNAL: i32 = 70;

#[derive(Debug, Error)]
#[error("{message}")]
pub struct CliExitError {
    pub code: i32,
    pub message: String,
}

pub fn exit_error(code: i32, message: impl Into<String>) -> Error {
    CliExitError {
        code,
        message: message.into(),
    }
    .into()
}

pub fn err<T>(code: i32, message: impl Into<String>) -> anyhow::Result<T> {
    Err(exit_error(code, message))
}

pub fn exit_code_for(err: &Error) -> i32 {
    if let Some(coded) = err.downcast_ref::<CliExitError>() {
        coded.code
    } else {
        EXIT_INTERNAL
    }
}
