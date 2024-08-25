use crate::{
    terror, token::StatelessResetToken, ConnectionId, SPACE_ID_DATA, SPACE_ID_HANDSHAKE,
    SPACE_ID_INITIAL,
};

use octets::{Octets, OctetsMut};
use rustls::quic::{DirectionalKeys, HeaderProtectionKey};

use std::fmt;

const MAX_PKT_NUM_LEN: usize = 4;
const SAMPLE_LEN: usize = 16;
pub const PACKET_LENGTH_ENCODING_LENGTH: usize = 4;

pub const LS_TYPE_BIT: u8 = 0x80;
pub const LONG_PACKET_TYPE: u8 = 0x30;
const PKT_NUM_LENGTH_MASK: u8 = 0x03;

pub const LONG_HEADER_TYPE_INITIAL: u8 = 0x00;
pub const LONG_HEADER_TYPE_HANDSHAKE: u8 = 0x02;

//packet and address, either source or destination
pub type Datagram = (Vec<u8>, String);

//encrypts a packet, pn_len is in bytes starting at one and header_end_off must include packet number
pub fn encrypt(
    packet: &mut OctetsMut,
    keys: &DirectionalKeys,
    pn: u32,
    payload_offset: usize,
) -> Result<usize, terror::Error> {
    let tag_len = keys.packet.tag_len();
    let packet_length = packet.off() + tag_len;

    //println!("packet pre encrypt: {:x?}", &packet.buf()[..packet_length]);

    let (mut p, _) = packet.split_at(packet_length)?;

    let pn_len = Header::calculate_pn_length(pn) as usize + 1;

    //encrypts the packet payload and copies the tag into the buffer
    let (mut header, mut payload_and_tag) = p.split_at(payload_offset)?;

    let (mut payload, mut tag_storage) =
        payload_and_tag.split_at(payload_and_tag.len() - tag_len)?;
    let tag = keys
        .packet
        .encrypt_in_place(pn as u64, header.as_mut(), payload.as_mut())
        .unwrap();

    //println!("tag: {:x?}", tag.as_ref());

    tag_storage.put_bytes(tag.as_ref())?;

    //encrypts the header
    let pn_offset = payload_offset - pn_len;
    let (mut header, sample) = p.split_at(pn_offset + 4)?;
    let (mut first, mut rest) = header.split_at(1)?;
    let pn_end = Ord::min(pn_offset + 3, rest.len());

    keys.header
        .encrypt_in_place(
            &sample.as_ref()[..keys.header.sample_len()],
            &mut first.as_mut()[0],
            &mut rest.as_mut()[pn_offset - 1..pn_end],
        )
        .unwrap();

    //println!("packet post encrypt: {:x?}", &packet.buf()[..packet_length]);

    Ok(packet_length)
}

pub fn encode_frame<T: Frame>(
    frame: &T,
    buffer: &mut octets::OctetsMut<'_>,
) -> Result<(), octets::BufferTooShortError> {
    //check for sufficient remaining size before encoding
    if frame.len() > buffer.cap() {
        return Err(octets::BufferTooShortError);
    }

    frame.to_bytes(buffer).unwrap();

    Ok(())
}

pub trait Frame {
    fn from_bytes(frame_code: &u8, bytes: &mut octets::OctetsMut<'_>) -> Self;

    fn to_bytes(
        &self,
        bytes: &mut octets::OctetsMut<'_>,
    ) -> Result<(), octets::BufferTooShortError>;

    fn len(&self) -> usize;
}

pub struct AckFrame {
    largest_acknowledged: u64,
    ack_delay: u64,
    ack_range_count: u64,
    first_ack_range: u64,
    ack_ranges: Vec<(u64, u64)>,

    //for ack type 0x03 ack frame contains ecn counts, rfc 9000 19.3.2
    ecn_counts: Option<(u64, u64, u64)>,

    len: usize,
}

impl AckFrame {
    pub fn into_pn_vec(self) -> Vec<u64> {
        let mut vec = Vec::from_iter(
            self.largest_acknowledged - self.first_ack_range..=self.largest_acknowledged,
        );

        for (gap, range) in &self.ack_ranges {
            let smallest = vec.first().unwrap();
            let to = smallest - gap - 1;
            let from = to - *range;
            let mut pns = Vec::from_iter(from..=to);
            pns.append(&mut vec);
            vec.append(&mut pns);
        }

        vec
    }

    //generates an ack frame from a vector of packet numbers. The vector has to be sorted in
    //descending order, i.e. the highest packet number has to be at index 0.
    pub fn from_packet_number_vec(packet_numbers: &[u64], ack_delay: u64) -> Self {
        let mut ack = Self::empty(ack_delay);
        ack.len = 1;
        //println!("len + 1 from frame code");
        let mut last_pn: u64 = 0;

        for (i, range) in Self::range_iterator_descending(packet_numbers).enumerate() {
            if i == 0 {
                //first range contains highest ack
                ack.add_highest_range(range[0], (range.len() - 1) as u64);
                //println!("first ack range: ha {:?} r {:?}", range[0], range.len() - 1);
                last_pn = range[range.len() - 1];
            } else {
                //append to ranges
                let gap: u64 = last_pn - range[0] - 1;
                //println!("gap {:?} = lpn {:?} - r0 {:?}", gap, last_pn, range[0]);
                last_pn = range[range.len() - 1];
                ack.add_range(gap, (range.len() - 1) as u64);
            }
        }

        ack.len += varint_length(ack.largest_acknowledged)
            + varint_length(ack.ack_delay)
            + varint_length(ack.ack_range_count)
            + varint_length(ack.first_ack_range);

        ack
    }

    //creates an iterator over a descending ordered vector which isolates slices, i.e. a sequence
    //of numbers where numbers decrease by exactly one
    fn range_iterator_descending(data: &[u64]) -> impl Iterator<Item = &[u64]> {
        let mut slice_start = 0;
        (0..data.len()).flat_map(move |i| {
            if i == data.len() - 1 || data[i] != data[i + 1] + 1 {
                let start = slice_start;
                slice_start = i + 1;
                Some(&data[start..=i])
            } else {
                None
            }
        })
    }

    //creates an empty ack frame with just the ack_delay
    fn empty(ack_delay: u64) -> Self {
        Self {
            largest_acknowledged: 0,
            ack_delay,
            ack_range_count: 0,
            first_ack_range: 0,
            ack_ranges: Vec::new(),
            ecn_counts: None,
            len: 0,
        }
    }

    fn add_highest_range(&mut self, largest_acknowledged: u64, first_ack_range: u64) {
        self.largest_acknowledged = largest_acknowledged;
        self.first_ack_range = first_ack_range;
    }

    fn add_range(&mut self, gap: u64, range: u64) {
        self.ack_ranges.push((gap, range));
        self.ack_range_count += 1;

        self.len += varint_length(gap);
        self.len += varint_length(range);
    }

    //TODO add support for ecn counts
    fn _add_ecn_counts(&mut self, ecn_counts: (u64, u64, u64)) {
        self.ecn_counts = Some(ecn_counts);

        self.len += varint_length(ecn_counts.0);
        self.len += varint_length(ecn_counts.1);
        self.len += varint_length(ecn_counts.2);
    }
}

impl Frame for AckFrame {
    fn from_bytes(frame_code: &u8, bytes: &mut octets::OctetsMut<'_>) -> Self {
        //begin doesnt account for frame code 0x06 so -1 (u8)
        let begin = bytes.off() - 1;
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
            len: bytes.off() - begin,
        }
    }

    fn to_bytes(
        &self,
        bytes: &mut octets::OctetsMut<'_>,
    ) -> Result<(), octets::BufferTooShortError> {
        if self.ecn_counts.is_some() {
            bytes.put_u8(0x03)?;
        } else {
            bytes.put_u8(0x02)?;
        }

        bytes.put_varint(self.largest_acknowledged)?;
        bytes.put_varint(self.ack_delay)?;
        bytes.put_varint(self.ack_range_count)?;
        bytes.put_varint(self.first_ack_range)?;

        for (gap, range_length) in &self.ack_ranges {
            bytes.put_varint(*gap)?;
            bytes.put_varint(*range_length)?;
        }

        if let Some(ecn) = self.ecn_counts {
            bytes.put_varint(ecn.0)?;
            bytes.put_varint(ecn.1)?;
            bytes.put_varint(ecn.2)?;
        }

        Ok(())
    }

    fn len(&self) -> usize {
        self.len
    }
}

pub struct CryptoFrame {
    offset: u64,
    crypto_data: Vec<u8>,
    len: usize,
}

impl CryptoFrame {
    pub fn new(offset: u64, crypto_data: Vec<u8>) -> Self {
        let len =
            1 + varint_length(offset) + varint_length(crypto_data.len() as u64) + crypto_data.len();
        Self {
            offset,
            crypto_data,
            len,
        }
    }
}

impl Frame for CryptoFrame {
    fn from_bytes(frame_code: &u8, bytes: &mut octets::OctetsMut<'_>) -> Self {
        let begin = bytes.off() - 1;
        let offset = bytes.get_varint().unwrap();

        CryptoFrame {
            offset,
            crypto_data: bytes.get_bytes_with_varint_length().unwrap().to_vec(),
            len: bytes.off() - begin,
        }
    }

    fn to_bytes(
        &self,
        bytes: &mut octets::OctetsMut<'_>,
    ) -> Result<(), octets::BufferTooShortError> {
        bytes.put_u8(0x06)?;
        bytes.put_varint(self.offset)?;
        bytes.put_varint(self.crypto_data.len().try_into().unwrap())?;
        bytes.put_bytes(self.crypto_data.as_ref())?;
        Ok(())
    }

    fn len(&self) -> usize {
        self.len
    }
}

impl CryptoFrame {
    pub fn data(&self) -> &[u8] {
        self.crypto_data.as_ref()
    }

    pub fn vec(&self) -> &Vec<u8> {
        &self.crypto_data
    }
}

pub struct NewTokenFrame {
    token_length: u64,
    token: Vec<u8>,
    len: usize,
}

impl Frame for NewTokenFrame {
    fn from_bytes(frame_code: &u8, bytes: &mut octets::OctetsMut<'_>) -> Self {
        let begin = bytes.off() - 1;
        let token_length = bytes.get_varint().unwrap();

        NewTokenFrame {
            token_length,
            token: bytes.get_bytes(token_length as usize).unwrap().to_vec(),
            len: bytes.off() - begin,
        }
    }

    fn to_bytes(
        &self,
        bytes: &mut octets::OctetsMut<'_>,
    ) -> Result<(), octets::BufferTooShortError> {
        Ok(())
    }

    fn len(&self) -> usize {
        self.len
    }
}

pub struct ConnectionCloseFrame {
    error_code: u64,
    frame_type: Option<u64>,
    reason_phrase_length: u64,
    reason_phrase: Vec<u8>,
    len: usize,
}

impl Frame for ConnectionCloseFrame {
    fn from_bytes(frame_code: &u8, bytes: &mut octets::OctetsMut<'_>) -> Self {
        let begin = bytes.off() - 1;
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
            len: bytes.off() - begin,
        }
    }

    fn to_bytes(
        &self,
        bytes: &mut octets::OctetsMut<'_>,
    ) -> Result<(), octets::BufferTooShortError> {
        Ok(())
    }

    fn len(&self) -> usize {
        self.len
    }
}

//TODO add retry token and long header type
#[derive(Default)]
pub struct Header {
    //header form and version specific bits
    pub hf: u8,
    pub version: u32,
    pub dcid: ConnectionId,
    pub scid: Option<ConnectionId>,
    pub token: Option<Vec<u8>>,

    //The following fields are under header protection
    pub packet_num: u32,
    pub packet_num_length: u8,

    //packet length including packet_num
    pub length: usize,

    //header length excluding packet num
    pub raw_length: usize,

    //packet number space for key retrieval, either 0, 1 or 2
    space: usize,
}

impl Header {
    pub fn new_long_header(
        long_header_type: u8,
        version: u32,
        packet_num: u32,
        dcid: &ConnectionId,
        scid: &ConnectionId,
        token: Option<Vec<u8>>,
        packet_length: usize,
    ) -> Result<Self, terror::Error> {
        let space: usize = match long_header_type {
            LONG_HEADER_TYPE_INITIAL => SPACE_ID_INITIAL,
            0x01 => SPACE_ID_DATA,
            LONG_HEADER_TYPE_HANDSHAKE => SPACE_ID_HANDSHAKE,
            0x03 => todo!("retry packets are not yet implemented"),
            _ => unreachable!("invalid long header type: {}", long_header_type),
        };

        if !matches!(long_header_type, 0x00..=0x03) {
            return Err(terror::Error::header_encoding_error(format!(
                "unsupported long header type {:?}",
                long_header_type
            )));
        }

        if long_header_type == 0x00 && token.is_none() {
            return Err(terror::Error::header_encoding_error(
                "token required for initial header",
            ));
        }

        let mut raw_length = 1 + 4 + 1 + dcid.len() + 1 + scid.len();

        if long_header_type == 0x00 {
            // token length is encoded as variable length integer
            let token_length_length = varint_length(token.as_ref().unwrap().len() as u64);

            raw_length += token_length_length + token.as_ref().unwrap().len();
        }

        //variable length packet length always encoded as length 4
        raw_length += PACKET_LENGTH_ENCODING_LENGTH;

        Ok(Header::new(
            0x01,
            long_header_type,
            0x00,
            0x00,
            version,
            dcid,
            Some(scid),
            packet_num,
            token,
            packet_length,
            raw_length,
            space,
        ))
    }

    pub fn new_short_header(
        spin_bit: u8,
        key_phase: u8,
        version: u32,
        packet_num: u32,
        dcid: &ConnectionId,
    ) -> Result<Self, terror::Error> {
        if !matches!(spin_bit, 0x00 | 0x01) {
            return Err(terror::Error::header_encoding_error(format!(
                "unsupported header spin bit {:?}",
                spin_bit
            )));
        }

        if !matches!(key_phase, 0x00 | 0x01) {
            return Err(terror::Error::header_encoding_error(format!(
                "unsupported header key phase {:?}",
                key_phase
            )));
        }

        let raw_length = 1 + dcid.len();

        Ok(Header::new(
            0x00, 0x00, spin_bit, key_phase, version, dcid, None, packet_num, None, 0, raw_length,
            2,
        ))
    }

    //not public because values are not error checked
    fn new(
        header_form: u8,
        long_header_type: u8,
        spin_bit: u8,
        key_phase: u8,
        version: u32,
        dcid: &ConnectionId,
        scid: Option<&ConnectionId>,
        packet_num: u32,
        token: Option<Vec<u8>>,
        length: usize,
        raw_length: usize,
        space: usize,
    ) -> Self {
        let packet_num_length = Header::calculate_pn_length(packet_num);
        let mut hf: u8 = 0x00;

        //set header form bit
        hf |= header_form << 7;

        //set fixed bit for every header type
        hf |= 1 << 6;

        hf |= spin_bit << 5;

        hf |= long_header_type << 4;

        hf |= key_phase << 2;

        hf |= packet_num_length;

        Self {
            hf,
            version,
            dcid: dcid.clone(),
            scid: scid.cloned(),
            packet_num,
            packet_num_length,
            token,
            length,
            raw_length,
            space,
        }
    }

    pub fn decrypt(
        &mut self,
        buffer: &mut [u8],
        header_key: &dyn HeaderProtectionKey,
    ) -> Result<usize, octets::BufferTooShortError> {
        let mut b = octets::OctetsMut::with_slice(buffer);
        b.skip(self.raw_length)?;

        let mut pn_and_sample = b.peek_bytes_mut(MAX_PKT_NUM_LEN + SAMPLE_LEN)?;
        let (mut pn_cipher, sample) = pn_and_sample.split_at(MAX_PKT_NUM_LEN)?;

        match header_key.decrypt_in_place(sample.as_ref(), &mut self.hf, pn_cipher.as_mut()) {
            Ok(_) => (),
            Err(error) => panic!("Error decrypting header: {}", error),
        }

        //write decrypted first byte back into buffer
        let (mut first_byte, _) = b.split_at(1)?;
        first_byte.as_mut()[0] = self.hf;

        self.packet_num_length = self.hf & PKT_NUM_LENGTH_MASK;

        self.packet_num = match self.packet_num_length {
            0 => u32::from(b.get_u8()?),
            1 => u32::from(b.get_u16()?),
            2 => b.get_u24()?,
            3 => b.get_u32()?,
            _ => return Err(octets::BufferTooShortError),
        };

        Ok(self.raw_length + self.packet_num_length as usize + 1)
    }

    //TODO retry & version negotiation packets
    pub fn to_bytes(
        &self,
        b: &mut octets::OctetsMut,
        lfo: &mut usize,
    ) -> Result<(), octets::BufferTooShortError> {
        b.put_u8(self.hf)?;

        if let Some(scid) = &self.scid {
            //long header
            b.put_u32(self.version)?;
            b.put_u8(self.dcid.len().try_into().unwrap())?;
            b.put_bytes(self.dcid.as_slice())?;
            b.put_u8(scid.len().try_into().unwrap())?;
            b.put_bytes(scid.as_slice())?;

            //initial
            if ((self.hf & LONG_PACKET_TYPE) >> 4) == 0x00 {
                let token = self.token.as_ref().unwrap();
                let token_length = token.len();

                b.put_varint(token_length.try_into().unwrap())?;
                b.put_bytes(token)?;
            }

            //packet length, always write as 4 byte varint to allow for later
            *lfo = b.off();
            b.put_varint_with_len(self.length as u64, PACKET_LENGTH_ENCODING_LENGTH)?;
        } else {
            //short header
            b.put_bytes(self.dcid.as_slice())?;
        }

        //packet number
        match self.packet_num_length {
            0 => b.put_u8(self.packet_num.try_into().unwrap())?,
            1 => b.put_u16(self.packet_num.try_into().unwrap())?,
            2 => b.put_u24(self.packet_num)?,
            3 => b.put_u32(self.packet_num)?,
            _ => unreachable!(
                "unsupported packet number length {}",
                self.packet_num_length
            ),
        };

        Ok(())
    }

    pub fn from_bytes(
        buffer: &[u8],
        dcid_len: usize,
    ) -> Result<Header, octets::BufferTooShortError> {
        let mut b = Octets::with_slice(buffer);
        let mut space: usize = 2;
        let hf = b.get_u8()?;

        if ((hf & LS_TYPE_BIT) >> 7) == 0 {
            //short packet
            let dcid = b.get_bytes(dcid_len)?;

            return Ok(Header {
                hf,
                version: 0,
                dcid: dcid.to_vec().into(),
                scid: None,
                packet_num: 0,
                packet_num_length: 0,
                token: None,
                length: 0,
                raw_length: b.off(),
                space,
            });
        }

        let v = b.get_u32()?;

        let dcid_length = b.get_u8()?; // TODO check for max cid len of 20
        let dcid = b.get_bytes(dcid_length as usize)?.to_vec();

        let scid_length = b.get_u8()?; // TODO check for max cid len of 20
        let scid = b.get_bytes(scid_length as usize)?.to_vec();

        let mut tok: Option<Vec<u8>> = None;

        match (hf & LONG_PACKET_TYPE) >> 4 {
            0x00 => {
                // Initial
                tok = Some(b.get_bytes_with_varint_length()?.to_vec());
                space = 0;
            }
            0x01 => (),        // Zero-RTT
            0x02 => space = 1, // Handshake
            0x03 => (),        // Retry
            _ => panic!("Fatal Error with packet type"),
        }

        let length = b.get_varint()? as usize;

        Ok(Header {
            hf,
            version: v,
            dcid: dcid.into(),
            scid: Some(scid.into()),
            packet_num: 0,
            packet_num_length: 0,
            token: tok,
            length,
            raw_length: b.off(),
            space,
        })
    }

    pub fn get_dcid(
        buffer: &[u8],
        dcid_len: usize,
    ) -> Result<ConnectionId, octets::BufferTooShortError> {
        let mut b = Octets::with_slice(buffer);
        let hf = b.get_u8()?;

        if ((hf & LS_TYPE_BIT) >> 7) == 0 {
            //short packet
            let dcid = b.get_bytes(dcid_len)?;
            return Ok(<Vec<u8> as Into<ConnectionId>>::into(dcid.to_vec()));
        }

        let _ = b.get_u32()?;

        let dcid_length = b.get_u8()?;
        Ok(<Vec<u8> as Into<ConnectionId>>::into(
            b.get_bytes(dcid_length as usize)?.to_vec(),
        ))
    }

    pub fn space(&self) -> usize {
        self.space
    }

    pub fn is_inital(&self) -> bool {
        ((self.hf & LS_TYPE_BIT) >> 7) == 1 && ((self.hf & LONG_PACKET_TYPE) >> 4) == 0
    }

    pub fn calculate_pn_length(packet_number: u32) -> u8 {
        match packet_number {
            0x00..=0xff => 0,
            0x0100..=0xffff => 1,
            0x010000..=0xffffff => 2,
            0x01000000..=0xffffffff => 3,
        }
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#b} version: {:#06x?} pn: {:#010x?} dcid: {} scid: 0x{} token:{:x?} length:{:?} raw_length:{:?}",
            self.hf,
            self.version,
            self.packet_num,
            self.dcid,
            self.scid
                .clone()
                .unwrap_or(ConnectionId::from_vec(Vec::new())),
            self.token.as_ref().unwrap_or(&vec![0u8; 0]),
            self.length,
            self.raw_length)
    }
}

pub fn varint_length(num: u64) -> usize {
    match num {
        0..=63 => 1,
        64..=16383 => 2,
        16384..=1073741823 => 3,
        1073741824..=4611686018427387903 => 4,
        _ => unreachable!("number exceeded abnormally large size"),
    }
}

#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    None = 0,
    Initial = 1,
    ZeroRtt = 2,
    Handshake = 3,
    Retry = 4,
    Short = 5,
}

impl From<usize> for PacketType {
    fn from(pns: usize) -> Self {
        match pns {
            0 => PacketType::Initial,
            1 => PacketType::Handshake,
            2 => PacketType::Short,
            _ => unreachable!("cannot convert packet number space outside of range 0..=2"),
        }
    }
}

impl From<PacketType> for String {
    fn from(pt: PacketType) -> String {
        match pt {
            PacketType::None => "None".to_string(),
            PacketType::Initial => "Initial".to_string(),
            PacketType::ZeroRtt => "ZeroRtt".to_string(),
            PacketType::Handshake => "Handshake".to_string(),
            PacketType::Retry => "Retry".to_string(),
            PacketType::Short => "Short".to_string(),
        }
    }
}

impl fmt::Display for PacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from(*self))
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    //TODO expand to other packet types through all pns
    #[test]
    fn test_intial_header_decoding_server_side() {
        let mut head_raw: [u8; 64] = [
            0xc3, 0x00, 0x00, 0x00, 0x01, 0x14, 0x8b, 0x36, 0x1e, 0xd4, 0x6c, 0xbf, 0xde, 0x7f,
            0xa3, 0x7e, 0xb4, 0xd6, 0xb9, 0xa6, 0x68, 0xf4, 0x49, 0x3e, 0x75, 0xf6, 0x08, 0x21,
            0x8a, 0xd5, 0x88, 0xe8, 0x40, 0x4a, 0xfb, 0x00, 0x44, 0x8a, 0x7f, 0x81, 0x22, 0x1f,
            0xf1, 0xf4, 0x4a, 0x64, 0x00, 0x6a, 0x32, 0xf4, 0xb3, 0x67, 0x99, 0xdc, 0x9e, 0x18,
            0xe1, 0x5c, 0x9f, 0xee, 0x48, 0x37, 0x7b, 0xc4,
        ];

        let mut partial_decode = Header::from_bytes(&head_raw, 8).unwrap();

        rustls::crypto::ring::default_provider()
            .install_default()
            .unwrap();

        let ikp = rustls::quic::Keys::initial(
            rustls::quic::Version::V1,
            rustls::crypto::ring::default_provider().cipher_suites[1]
                .tls13()
                .unwrap(),
            rustls::crypto::ring::default_provider().cipher_suites[1]
                .tls13()
                .unwrap()
                .quic
                .unwrap(),
            &partial_decode.dcid.id,
            rustls::Side::Server,
        );

        let header_length = match partial_decode.decrypt(&mut head_raw, ikp.remote.header.as_ref())
        {
            Ok(s) => s,
            Err(error) => panic!("Error: {}", error),
        };

        assert_eq!(header_length, 39);
        assert_eq!(partial_decode.version, 1);
        assert_eq!(partial_decode.packet_num, 0);
        assert_eq!(partial_decode.packet_num_length, 0);
        assert_eq!(partial_decode.length, 1162);
        assert_eq!(partial_decode.raw_length, 38);
    }

    #[test]
    fn test_ack_frame_creation_1() {
        let pns: Vec<u64> = vec![10, 9, 8, 6, 5, 4, 2, 1, 0];
        let ack = AckFrame::from_packet_number_vec(&pns, 200);

        assert_eq!(ack.largest_acknowledged, 10);
        assert_eq!(ack.first_ack_range, 2);
        assert_eq!(ack.ack_range_count, 2);
        assert_eq!(ack.ack_ranges[0], (1, 2));
        assert_eq!(ack.ack_ranges[0], (1, 2));
        assert_eq!(ack.len, 10);
    }

    #[test]
    fn test_ack_frame_creation_2() {
        let pns: Vec<u64> = vec![10, 9, 3, 2, 1, 0];
        let ack = AckFrame::from_packet_number_vec(&pns, 200);

        assert_eq!(ack.largest_acknowledged, 10);
        assert_eq!(ack.first_ack_range, 1);
        assert_eq!(ack.ack_range_count, 1);
        assert_eq!(ack.ack_ranges[0], (5, 3));
        assert_eq!(ack.len, 8);
    }

    #[test]
    fn test_ack_frame_to_pn_vec() {
        let pns: Vec<u64> = vec![10, 9, 8, 6, 5, 4, 2, 1, 0];
        let ack = AckFrame::from_packet_number_vec(&pns, 200);

        let vec = ack.into_pn_vec();

        let expected: Vec<u64> = vec![0, 1, 2, 4, 5, 6, 8, 9, 10];

        assert_eq!(vec, expected);
    }
    #[test]
    fn test_long_initial_header_creation() {
        let dcid = ConnectionId::from_vec(vec![0x34, 0xa7, 0x84, 0xef, 0x34, 0xa7, 0x84, 0xef]);
        let scid = ConnectionId::from_vec(vec![0xd5, 0x85, 0x23, 0x1b, 0xd5, 0x85, 0x23, 0x1b]);
        let header = Header::new_long_header(0x00, 1, 0, &dcid, &scid, Some(vec![]), 1201).unwrap();

        let mut vec = vec![0u8; 29];

        let mut b = octets::OctetsMut::with_slice(&mut vec);

        let mut length_offset: usize = 0;
        header.to_bytes(&mut b, &mut length_offset).unwrap();

        let expected = vec![
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x34, 0xa7, 0x84, 0xef, 0x34, 0xa7, 0x84, 0xef,
            0x08, 0xd5, 0x85, 0x23, 0x1b, 0xd5, 0x85, 0x23, 0x1b, 0x00, 0x80, 0x00, 0x04, 0xb1,
            0x00,
        ];

        assert_eq!(vec, expected);
        assert_eq!(header.raw_length, 28);
    }

    //#[test]
    //fn test_long_retry_header_creation() {}

    #[test]
    fn test_long_handshake_header_creation() {
        let dcid = ConnectionId::from_vec(vec![0x34, 0xa7, 0x84, 0xef, 0x34, 0xa7, 0x84, 0xef]);
        let scid = ConnectionId::from_vec(vec![0xd5, 0x85, 0x23, 0x1b, 0xd5, 0x85, 0x23, 0x1b]);
        let header = Header::new_long_header(0x02, 1, 1, &dcid, &scid, None, 3200).unwrap();

        let mut vec = vec![0u8; 28];

        let mut b = octets::OctetsMut::with_slice(&mut vec);

        let mut length_offset: usize = 0;
        header.to_bytes(&mut b, &mut length_offset).unwrap();

        let expected = vec![
            0xe0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x34, 0xa7, 0x84, 0xef, 0x34, 0xa7, 0x84, 0xef,
            0x08, 0xd5, 0x85, 0x23, 0x1b, 0xd5, 0x85, 0x23, 0x1b, 0x80, 0x00, 0x0c, 0x80, 0x01,
        ];

        assert_eq!(vec, expected);
        assert_eq!(header.raw_length, 27);
    }

    #[test]
    fn test_long_zero_rtt_header_creation() {
        let dcid = ConnectionId::from_vec(vec![0x34, 0xa7, 0x84, 0xef, 0x34, 0xa7, 0x84, 0xef]);
        let scid = ConnectionId::from_vec(vec![0xd5, 0x85, 0x23, 0x1b, 0xd5, 0x85, 0x23, 0x1b]);
        let header = Header::new_long_header(0x01, 1, 0, &dcid, &scid, None, 3200).unwrap();

        let mut vec = vec![0u8; 28];

        let mut b = octets::OctetsMut::with_slice(&mut vec);

        let mut length_offset: usize = 0;
        header.to_bytes(&mut b, &mut length_offset).unwrap();

        let expected = vec![
            0xd0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x34, 0xa7, 0x84, 0xef, 0x34, 0xa7, 0x84, 0xef,
            0x08, 0xd5, 0x85, 0x23, 0x1b, 0xd5, 0x85, 0x23, 0x1b, 0x80, 0x00, 0x0c, 0x80, 0x00,
        ];

        assert_eq!(vec, expected);
        assert_eq!(header.raw_length, 27);
    }

    #[test]
    fn test_short_header_creation() {
        let dcid = ConnectionId::from_vec(vec![0x34, 0xa7, 0x84, 0xef, 0x34, 0xa7, 0x84, 0xef]);
        let header = Header::new_short_header(0x00, 0x01, 1, 380, &dcid).unwrap();

        let mut vec = vec![0u8; 11];

        let mut b = octets::OctetsMut::with_slice(&mut vec);

        let mut length_offset: usize = 0;
        header.to_bytes(&mut b, &mut length_offset).unwrap();

        let expected = vec![
            0x45, 0x34, 0xa7, 0x84, 0xef, 0x34, 0xa7, 0x84, 0xef, 0x01, 0x7c,
        ];

        assert_eq!(vec, expected);
        assert_eq!(header.raw_length, 9);
    }
}
