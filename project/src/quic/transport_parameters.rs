use octets::{BufferTooShortError, OctetsMut};
use std::fmt;

//RFC 9000 Section 18: Transport Parameter Encoding
//Id and length fields are defined as variable length integers, we store them in human
//readable form and only encode/decode if needed with Octets
pub struct TransportParameter {
    id: u64,
    length: u64,
    value: Vec<u8>,
}

impl TransportParameter {
    pub fn new(id: u64, length: u64, value: Vec<u8>) -> Self {
        Self { id, length, value }
    }

    pub fn decode(data: &mut OctetsMut<'_>) -> Result<Self, BufferTooShortError> {
        let id = data.get_varint()?;
        let length = data.get_varint()?;
        let value = data.get_bytes(length as usize).unwrap();
        Ok(Self {
            id,
            length,
            value: value.to_vec(),
        })
    }

    pub fn encode(&self, data: &mut OctetsMut<'_>) -> Result<(), BufferTooShortError> {
        data.put_varint(self.id)?;
        data.put_varint(self.length)?;
        data.put_bytes(&self.value)?;
        Ok(())
    }
}

impl fmt::Display for TransportParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:x} len:{:x} data:{}",
            self.id,
            self.length,
            self.value
                .iter()
                .map(|val| format!("{:x}", val))
                .collect::<Vec<String>>()
                .join(" ")
        )
    }
}
