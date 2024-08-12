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
    pub fn kind(&self) -> u64 {
        self.code
    }

    taurus_error!(fatal, 0x11);
    taurus_error!(unknown_connection, 0x12);
    taurus_error!(socket_error, 0x13);
    taurus_error!(header_encoding_error, 0x14);
    taurus_error!(packet_encoding_error, 0x15);
    taurus_error!(buffer_size_error, 0x16);
    taurus_error!(no_cipher_suite, 0x17);
    taurus_error!(crypto_error, 0x18);
    taurus_error!(taurus_misc_error, 0xff);

    pub fn quic_transport_error<T>(reason: T, code: QuicTransportError) -> Self
    where
        T: Into<String>,
    {
        let mut msg = format!("{code} ");
        msg.push_str(&reason.into());
        Self {
            code: code as u64,
            msg,
        }
    }
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
}

impl fmt::Display for QuicTransportError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            QuicTransportError::NoError => write!(f, "no error"),
            QuicTransportError::InternalError => write!(f, "internal error"),
            QuicTransportError::ConnectionRefused => write!(f, "connection refused"),
            QuicTransportError::FlowControlError => write!(f, "flow control error"),
            QuicTransportError::StreamLimitError => write!(f, "stream limit error"),
            QuicTransportError::StreamStateError => write!(f, "stream state error"),
            QuicTransportError::FinalSizeError => write!(f, "final size error"),
            QuicTransportError::FrameEncodingError => write!(f, "frame encoding error"),
            QuicTransportError::TransportParameterError => {
                write!(f, "transport parameter error")
            }
            QuicTransportError::ConnectionIdLimitError => {
                write!(f, "connection id limit error")
            }
            QuicTransportError::ProtocolViolation => write!(f, "protocol violation"),
            QuicTransportError::InvalidToken => write!(f, "invalid token"),
            QuicTransportError::ApplicationError => write!(f, "application error"),
            QuicTransportError::CryptoBufferExceeded => write!(f, "crypto buffer exceeded"),
            QuicTransportError::KeyUpdateError => write!(f, "key update error"),
            QuicTransportError::AeadLimitReached => write!(f, "aead limit reached"),
            QuicTransportError::NoViablePath => write!(f, "no viable path"),
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
