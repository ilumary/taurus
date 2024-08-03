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
    taurus_error!(packet_encoding_error, 0x04);
    taurus_error!(buffer_size_error, 0x05);
    taurus_error!(no_cipher_suite, 0x06);
    taurus_error!(crypto_error, 0x07);
    taurus_error!(quic_protocol_violation, 0x0a);
    taurus_error!(taurus_misc_error, 0xff);
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

#[repr(u64)]
#[derive(Copy, Clone)]
pub enum QuicTransportError {
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
    CryptoError(CryptoError),
}

impl fmt::Display for QuicTransportError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            QuicTransportError::NoError => write!(f, "0x00 no error"),
            QuicTransportError::InternalError => write!(f, "0x01 internal error"),
            QuicTransportError::ConnectionRefused => write!(f, "0x02 connection refused"),
            QuicTransportError::FlowControlError => write!(f, "0x03 flow control error"),
            QuicTransportError::StreamLimitError => write!(f, "0x04 stream limit error"),
            QuicTransportError::StreamStateError => write!(f, "0x05 stream state error"),
            QuicTransportError::FinalSizeError => write!(f, "0x06 final size error"),
            QuicTransportError::FrameEncodingError => write!(f, "0x07 frame encoding error"),
            QuicTransportError::TransportParameterError => {
                write!(f, "0x08 transport parameter error")
            }
            QuicTransportError::ConnectionIdLimitError => {
                write!(f, "0x09 connection id limit error")
            }
            QuicTransportError::ProtocolViolation => write!(f, "0x0a protocol violation"),
            QuicTransportError::InvalidToken => write!(f, "0x0b invalid token"),
            QuicTransportError::ApplicationError => write!(f, "0x0c application error"),
            QuicTransportError::CryptoBufferExceeded => write!(f, "0x0d crypto buffer exceeded"),
            QuicTransportError::KeyUpdateError => write!(f, "0x0e key update error"),
            QuicTransportError::AeadLimitReached => write!(f, "0x0f aead limit reached"),
            QuicTransportError::NoViablePath => write!(f, "0x10 no viable path"),
            QuicTransportError::CryptoError(c) => write!(f, "{} crypto error", c),
        }
    }
}

// 0x0100 - 0x01ff
#[derive(Copy, Clone)]
pub struct CryptoError {
    code: u64,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.code)
    }
}
