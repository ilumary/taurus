use crate::ConnectionId;

pub struct StatelessResetToken {
    pub token: [u8; 0x10],
}

impl StatelessResetToken {
    pub fn new(key: &ring::hmac::Key, id: &ConnectionId) -> Self {
        let signature = ring::hmac::sign(key, id.as_arr()).as_ref().to_vec();
        let mut result = [0u8; 0x10];
        result.copy_from_slice(&signature[..0x10]);
        Self { token: result }
    }
}
