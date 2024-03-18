#![allow(non_snake_case)]
use std::error::Error as SError;
use std::fmt;

#[derive(Debug)]
pub struct Error {
    code: u64,
    msg: String,
}

macro_rules! quic_error {
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
    quic_error!(fatal, 0x00);
    quic_error!(unknown_connection, 0x01);
    quic_error!(socket_error, 0x02);
    quic_error!(header_encoding_error, 0x03);
    quic_error!(packet_size_error, 0x04);
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x} {}", self.code, self.msg)
    }
}

impl SError for Error {
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
