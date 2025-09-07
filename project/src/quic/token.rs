use crate::cid;

#[derive(PartialEq, Default, Clone, Copy)]
pub struct StatelessResetToken {
    pub token: [u8; 0x10],
}

impl StatelessResetToken {
    pub fn new(key: &ring::hmac::Key, id: &cid::Id) -> Self {
        let signature = ring::hmac::sign(key, id.as_slice()).as_ref().to_vec();
        let mut result = [0u8; 0x10];
        result.copy_from_slice(&signature[..0x10]);
        Self { token: result }
    }

    pub fn verify(&self, key: &ring::hmac::Key, id: &cid::Id) -> bool {
        let expected = StatelessResetToken::new(key, id);
        self == &expected
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

#[cfg(test)]
mod tests {
    use super::*;

    // a helper to make deterministic test keys
    fn test_key() -> ring::hmac::Key {
        let bytes = [0xAB; 32];
        ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &bytes)
    }

    #[test]
    fn stateless_reset_token_generation() {
        let key = test_key();
        let id = cid::Id::from(vec![0x01, 0x02, 0x03, 0x04]);

        // simulate server generating a reset token for a connection
        let token = StatelessResetToken::new(&key, &id);

        // simulate client verifying that token against the original cid
        assert!(token.verify(&key, &id));

        // wrong id should not verify
        let other_id = cid::Id::from(vec![0xAA, 0xBB, 0xCC, 0xDD]);
        assert!(!token.verify(&key, &other_id));

        // wrong key should not verify
        let bad_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[0xFF; 32]);
        assert!(!token.verify(&bad_key, &id));
    }
}
