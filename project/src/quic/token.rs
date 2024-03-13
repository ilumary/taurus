use crate::ConnectionId;

pub struct StatelessResetToken {
    pub token: [u8; 0x10],
}

impl StatelessResetToken {
    pub fn new(key: &ring::hmac::Key, id: &ConnectionId) -> Self {
        let signature = ring::hmac::sign(key, id.as_slice()).as_ref().to_vec();
        let mut result = [0u8; 0x10];
        result.copy_from_slice(&signature[..0x10]);
        Self { token: result }
    }
}

impl From<Vec<u8>> for StatelessResetToken {
    fn from(v: Vec<u8>) -> Self {
        StatelessResetToken {
            token: v.try_into().unwrap_or_else(|v: Vec<u8>| {
                panic!(
                    "Error converting vec of length {} to array of length 0x10",
                    v.len()
                )
            }),
        }
    }
}
