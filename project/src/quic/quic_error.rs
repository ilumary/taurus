#![allow(non_snake_case)]
use std::error::Error as SError;
use std::fmt;

#[derive(Debug)]
pub struct Error {
    code: u64,
    msg: String,
}

impl Error {
    //TODO create makro
    pub fn INTERNAL_FATAL_ERROR<T>(reason: T) -> Self
    where
        T: Into<String>,
    {
        Self {
            code: 0x00,
            msg: reason.into(),
        }
    }

    pub fn CRYPTO_ERROR<T>(reason: T) -> Self
    where
        T: Into<String>,
    {
        Self {
            code: 0x01,
            msg: reason.into(),
        }
    }

    pub fn PARSE_ERROR<T>(reason: T) -> Self
    where
        T: Into<String>,
    {
        Self {
            code: 0x02,
            msg: reason.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x} {}", self.code, self.msg)
    }
}

impl SError for Error {
    fn description(&self) -> &str {
        &self.msg
    }
}
