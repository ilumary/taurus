use crate::{token::StatelessResetToken, ConnectionId};

pub trait Frame {
    fn from_bytes(frame_code: &u8, bytes: &mut octets::OctetsMut<'_>) -> Self;

    //fn to_bytes(&self, bytes: &mut octets::OctetsMut<'_>);

    //fn len(&self)
}

pub struct AckFrame {
    largest_acknowledged: u64,
    ack_delay: u64,
    ack_range_count: u64,
    first_ack_range: u64,
    ack_ranges: Vec<(u64, u64)>,

    //for ack type 0x03 ack frame contains ecn counts, rfc 9000 19.3.2
    ecn_counts: Option<(u64, u64, u64)>,
}

impl Frame for AckFrame {
    fn from_bytes(frame_code: &u8, bytes: &mut octets::OctetsMut<'_>) -> Self {
        let largest_acknowledged = bytes.get_varint().unwrap();
        let ack_delay = bytes.get_varint().unwrap();
        let ack_range_count = bytes.get_varint().unwrap();
        let first_ack_range = bytes.get_varint().unwrap();
        let mut ack_ranges = Vec::<(u64, u64)>::new();
        let mut ecn_counts: Option<(u64, u64, u64)> = None;

        for _ in 0..ack_range_count {
            ack_ranges.push((bytes.get_varint().unwrap(), bytes.get_varint().unwrap()));
        }

        if *frame_code == 0x03 {
            ecn_counts = Some((
                bytes.get_varint().unwrap(),
                bytes.get_varint().unwrap(),
                bytes.get_varint().unwrap(),
            ));
        }

        AckFrame {
            largest_acknowledged,
            ack_delay,
            ack_range_count,
            first_ack_range,
            ack_ranges,
            ecn_counts,
        }
    }
}

pub struct CryptoFrame {
    offset: u64,
    crypto_data: Vec<u8>,
}

impl Frame for CryptoFrame {
    fn from_bytes(frame_code: &u8, bytes: &mut octets::OctetsMut<'_>) -> Self {
        let offset = bytes.get_varint().unwrap();

        CryptoFrame {
            offset,
            crypto_data: bytes.get_bytes_with_varint_length().unwrap().to_vec(),
        }
    }
}

impl CryptoFrame {
    pub fn data(&self) -> &[u8] {
        self.crypto_data.as_ref()
    }

    pub fn vec(&self) -> &Vec<u8> {
        &self.crypto_data
    }

    pub fn len(&self) -> usize {
        self.crypto_data.len()
    }
}

pub struct NewTokenFrame {
    token_length: u64,
    token: Vec<u8>,
}

impl Frame for NewTokenFrame {
    fn from_bytes(frame_code: &u8, bytes: &mut octets::OctetsMut<'_>) -> Self {
        let token_length = bytes.get_varint().unwrap();

        NewTokenFrame {
            token_length,
            token: bytes.get_bytes(token_length as usize).unwrap().to_vec(),
        }
    }
}

pub struct StreamFrame {
    pub(crate) stream_id: u64,
    pub(crate) offset: Option<u64>,
    pub(crate) length: Option<u64>,
    pub(crate) fin_bit_set: bool,
}

impl Frame for StreamFrame {
    fn from_bytes(frame_code: &u8, bytes: &mut octets::OctetsMut<'_>) -> Self {
        let stream_id = bytes.get_varint().unwrap();
        let mut offset: Option<u64> = None;
        let mut length: Option<u64> = None;
        let mut fin_bit_set = false;

        if (*frame_code & 0x04) != 0 {
            offset = Some(bytes.get_varint().unwrap());
        }

        if (*frame_code & 0x02) != 0 {
            length = Some(bytes.get_varint().unwrap());
        }

        if (*frame_code & 0x01) != 0 {
            fin_bit_set = true;
        }

        StreamFrame {
            stream_id,
            offset,
            length,
            fin_bit_set,
        }
    }

    //fn to_bytes()
}

impl StreamFrame {
    fn _to_bytes_with_data(&self, data: &[u8], bytes: &mut octets::OctetsMut) {
        //self.to_bytes();
        //bytes.put_bytes(data);
    }
}

pub struct NewConnectionIdFrame {
    sequence_number: u64,
    retire_prior_to: u64,
    length: u8,
    connection_id: ConnectionId,
    stateless_reset_token: StatelessResetToken,
}

impl Frame for NewConnectionIdFrame {
    fn from_bytes(frame_code: &u8, bytes: &mut octets::OctetsMut<'_>) -> Self {
        let sequence_number = bytes.get_varint().unwrap();
        let retire_prior_to = bytes.get_varint().unwrap();
        let length = bytes.get_u8().unwrap();
        let connection_id = ConnectionId::from(bytes.get_bytes(length as usize).unwrap().to_vec());
        let stateless_reset_token =
            StatelessResetToken::from(bytes.get_bytes(0x10).unwrap().to_vec());

        NewConnectionIdFrame {
            sequence_number,
            retire_prior_to,
            length,
            connection_id,
            stateless_reset_token,
        }
    }
}

pub struct ConnectionCloseFrame {
    error_code: u64,
    frame_type: Option<u64>,
    reason_phrase_length: u64,
    reason_phrase: Vec<u8>,
}

impl Frame for ConnectionCloseFrame {
    fn from_bytes(frame_code: &u8, bytes: &mut octets::OctetsMut<'_>) -> Self {
        let error_code = bytes.get_varint().unwrap();
        let mut frame_type: Option<u64> = None;

        if *frame_code == 0x1c {
            frame_type = Some(bytes.get_varint().unwrap());
        }

        let reason_phrase_length = bytes.get_varint().unwrap();
        let reason_phrase = bytes
            .get_bytes(reason_phrase_length as usize)
            .unwrap()
            .to_vec();

        ConnectionCloseFrame {
            error_code,
            frame_type,
            reason_phrase_length,
            reason_phrase,
        }
    }
}
