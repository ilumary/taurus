#![allow(non_snake_case)]
use std::fmt;

#[derive(Debug)]
pub struct Error {
    code: u64,
    msg: String,
}

macro_rules! taurus_error {
    ($name:ident, $code:expr) => {
        pub fn $name<T>(reason: T) -> Self
        where
            T: Into<String>,
        {
            Self {
                code: $code,
                msg: reason.into(),
            }
        }
    };
}

impl Error {
    taurus_error!(fatal, 0x00);
    taurus_error!(unknown_connection, 0x01);
    taurus_error!(socket_error, 0x02);
    taurus_error!(header_encoding_error, 0x03);
    taurus_error!(packet_size_error, 0x04);
    taurus_error!(no_cipher_suite, 0x05);
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x} {}", self.code, self.msg)
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        &self.msg
    }
}

enum QuicTransportErrors {
    NoError = 0x00,
    InternalError = 0x01,
    ConnectionRefused = 0x02,
    FlowControlError = 0x03,
    StreamLimitError = 0x04,
    StreamStateError = 0x05,
    FinalSizeError = 0x06,
    FrameEncodingError = 0x07,
    TransportParameterError = 0x08,
    ConnectionIdLimitError = 0x09,
    ProtocolViolation = 0x0a,
    InvalidToken = 0x0b,
    ApplicationError = 0x0c,
    CryptoBufferExceeded = 0x0d,
    KeyUpdateError = 0x0e,
    AeadLimitReached = 0x0f,
    NoViablePath = 0x10,
}

// 0x0100 - 0x01ff
struct CryptoError {
    code: u64,
}
