use crate::{terror, token::StatelessResetToken, ConnectionId, TSDistributor};

use rustls::quic::HeaderProtectionKey;

use std::marker::PhantomData;

const MAX_PKT_NUM_LEN: u8 = 4;
const SAMPLE_LEN: usize = 16;

pub const LS_TYPE_BIT: u8 = 0x80;
const LONG_PACKET_TYPE: u8 = 0x30;
const PKT_NUM_LENGTH_MASK: u8 = 0x03;

pub const LONG_HEADER_TYPE_INITIAL: u8 = 0x00;
pub const LONG_HEADER_TYPE_HANDSHAKE: u8 = 0x02;

//packet and address, either source or destination
pub type Datagram = (Vec<u8>, String);

//early packet with partial header decode
pub type EarlyDatagram = (Vec<u8>, String, Header);

//inital packet with early datagram and distributor
pub type InitialDatagram = (
    Vec<u8>,
    String,
    Header,
    TSDistributor,
    std::sync::Arc<tokio::net::UdpSocket>,
);

//Required for full packet
pub struct PacketBody;
pub struct PacketHeader;
pub struct PacketEncoder;
pub type Completed = (PacketBody, PacketHeader, PacketEncoder);

//Packet Builder
pub struct PacketBuilder<'a, S = ((), (), ())> {
    dgram: &'a mut [u8],

    //packet
    header: Header,
    body: Vec<u8>,
    packet_length: usize,
    quic_version: u32,

    // header_end incl. packet number
    header_end_off: usize,

    // required because we never use the zero-sized types
    phantom: PhantomData<S>,
}

// private to control how Thing can be constructed
fn new_packet_builder<S>(
    dgram: &mut [u8],
    header: Header,
    body: Vec<u8>,
    packet_length: usize,
    quic_version: u32,
    header_end_off: usize,
) -> PacketBuilder<S> {
    PacketBuilder {
        dgram,
        header,
        body,
        packet_length,
        quic_version,
        header_end_off,
        phantom: PhantomData,
    }
}

impl<'a> PacketBuilder<'a> {
    pub fn new(quic_version: u32, dgram: &'a mut [u8]) -> Self {
        new_packet_builder(dgram, Header::default(), Vec::new(), 1200, quic_version, 0)
    }
}

impl<'a, B, H, C> PacketBuilder<'a, (B, H, C)> {
    pub fn with_body(self, body: Vec<u8>) -> PacketBuilder<'a, (PacketBody, H, C)> {
        new_packet_builder(
            self.dgram,
            self.header,
            body,
            self.packet_length,
            self.quic_version,
            self.header_end_off,
        )
    }

    pub fn with_long_header(
        self,
        long_header_type: u8,
        packet_number: u32,
        dcid: &ConnectionId,
        scid: &ConnectionId,
        token: Option<Vec<u8>>,
    ) -> Result<PacketBuilder<'a, (B, PacketHeader, C)>, terror::Error> {
        let packet_number_length = Header::calculate_pn_length(packet_number);
        let packet_length = self.body.len() + (packet_number_length + 1) as usize;

        let header = Header::new_long_header(
            long_header_type,
            self.quic_version,
            packet_number,
            dcid,
            scid,
            token,
            packet_length,
        )?;

        Ok(new_packet_builder(
            self.dgram,
            header,
            self.body,
            self.packet_length,
            self.quic_version,
            self.header_end_off,
        ))
    }

    pub fn with_short_header(
        self,
        packet_number: u32,
        dcid: &'a ConnectionId,
        spin_bit: u8,
        key_phase: u8,
    ) -> Result<PacketBuilder<(B, PacketHeader, C)>, terror::Error> {
        let header =
            Header::new_short_header(spin_bit, key_phase, self.quic_version, packet_number, dcid)?;

        Ok(new_packet_builder(
            self.dgram,
            header,
            self.body,
            self.packet_length,
            self.quic_version,
            self.header_end_off,
        ))
    }
}

impl<'a, E> PacketBuilder<'a, (PacketBody, PacketHeader, E)> {
    // encodes the packet and its header into the datagram, can only be called after body and
    // header have been specified
    pub fn encode(mut self) -> Result<(usize, PacketBuilder<'a, Completed>), terror::Error> {
        //calculate required buffer length
        let mut required_space =
            self.header.raw_length + self.header.packet_num_length as usize + 1 + self.body.len();

        //check for minimum size
        if required_space < 1200 {
            required_space = 1200;
            self.header.length = 1200 - self.header.raw_length;
        }

        if self.dgram.len() < required_space {
            return Err(terror::Error::buffer_size_error(
                "Datagram buffer has insufficient remaining size for packet",
            ));
        }

        let mut b = octets::OctetsMut::with_slice(self.dgram);

        //encode header
        if let Err(err) = self.header.to_bytes(&mut b) {
            return Err(terror::Error::buffer_size_error(format!(
                "Fatal error while encoding header: {}",
                err
            )));
        }

        self.header_end_off = b.off();

        //encode body
        if let Err(err) = b.put_bytes(&self.body) {
            return Err(terror::Error::buffer_size_error(format!(
                "Fatal error while encoding packet body: {}",
                err
            )));
        }

        assert!(b.off() <= required_space, "Fatal error");

        if b.off() < required_space {
            b.skip(required_space - b.off()).unwrap();
        }

        Ok((
            b.off(),
            new_packet_builder(
                self.dgram,
                self.header,
                self.body,
                self.packet_length,
                self.quic_version,
                self.header_end_off,
            ),
        ))
    }
}

impl<'a> PacketBuilder<'a, Completed> {
    //encrypts the packet, and returns new PacketBuilder in original state
    pub fn encrypt(self, keys: &'a rustls::quic::Keys) -> Result<(), terror::Error> {
        //isolate actual package
        let (dgram, _) = self.dgram.split_at_mut(self.packet_length);

        println!("NON ENCRYPT: {:x?}", &dgram);

        //encrypts the packet payload and copies the tag into the buffer
        let (header, payload_tag) = dgram.split_at_mut(self.header_end_off);
        let (payload, tag_storage) =
            payload_tag.split_at_mut(payload_tag.len() - keys.local.packet.tag_len());
        let tag = keys
            .local
            .packet
            .encrypt_in_place(self.header.packet_num as u64, &*header, payload)
            .unwrap();
        tag_storage.copy_from_slice(tag.as_ref());

        //encrypts the header
        let pn_offset = self.header_end_off - (self.header.packet_num_length as usize + 1);
        let (header, sample) = dgram.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        keys.local
            .header
            .encrypt_in_place(
                &sample[..keys.local.header.sample_len()],
                &mut first[0],
                &mut rest[pn_offset - 1..pn_end],
            )
            .unwrap();

        println!("ENCRYPT: {:x?}", &dgram);

        Ok(())
    }
}

pub fn encode_frame<T: Frame>(
    frame: &T,
    bytes: &mut octets::OctetsMut<'_>,
) -> Result<usize, octets::BufferTooShortError> {
    frame.to_bytes(bytes)
}

pub trait Frame {
    fn from_bytes(frame_code: &u8, bytes: &mut octets::OctetsMut<'_>) -> Self;

    fn to_bytes(
        &self,
        bytes: &mut octets::OctetsMut<'_>,
    ) -> Result<usize, octets::BufferTooShortError>;
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

impl AckFrame {
    //generates an ack frame from a vector of packet numbers. The vector has to be sorted in
    //descending order, i.e. the highest packet number has to be at index 0.
    pub fn from_packet_number_vec(packet_numbers: &[u64]) -> Self {
        let mut ack = Self::empty(100);
        let mut last_pn: u64 = 0;

        for (i, range) in Self::range_iterator_descending(packet_numbers).enumerate() {
            if i == 0 {
                //first range contains highest ack
                ack.add_highest_range(range[0], (range.len() - 1) as u64);
                println!("first ack range: ha {:?} r {:?}", range[0], range.len() - 1);
                last_pn = range[range.len() - 1];
            } else {
                //append to ranges
                let gap: u64 = last_pn - range[0] - 1;
                println!("gap {:?} = lpn {:?} - r0 {:?}", gap, last_pn, range[0]);
                last_pn = range[range.len() - 1];
                ack.add_range(gap, (range.len() - 1) as u64);
            }
        }

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
        }
    }

    fn add_highest_range(&mut self, largest_acknowledged: u64, first_ack_range: u64) {
        self.largest_acknowledged = largest_acknowledged;
        self.first_ack_range = first_ack_range;
    }

    fn add_range(&mut self, gap: u64, range: u64) {
        self.ack_ranges.push((gap, range));
        self.ack_range_count += 1;
    }

    fn add_ecn_counts(&mut self, ecn_counts: (u64, u64, u64)) {
        self.ecn_counts = Some(ecn_counts);
    }
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

    fn to_bytes(
        &self,
        bytes: &mut octets::OctetsMut<'_>,
    ) -> Result<usize, octets::BufferTooShortError> {
        let start = bytes.off();

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

        Ok(bytes.off() - start)
    }
}

pub struct CryptoFrame {
    offset: u64,
    crypto_data: Vec<u8>,
}

impl CryptoFrame {
    pub fn new(offset: u64, crypto_data: Vec<u8>) -> Self {
        Self {
            offset,
            crypto_data,
        }
    }
}

impl Frame for CryptoFrame {
    fn from_bytes(frame_code: &u8, bytes: &mut octets::OctetsMut<'_>) -> Self {
        let offset = bytes.get_varint().unwrap();

        CryptoFrame {
            offset,
            crypto_data: bytes.get_bytes_with_varint_length().unwrap().to_vec(),
        }
    }

    fn to_bytes(
        &self,
        bytes: &mut octets::OctetsMut<'_>,
    ) -> Result<usize, octets::BufferTooShortError> {
        bytes.put_u8(0x06)?;
        let off_len = bytes.put_varint(self.offset)?.len();
        let data_len_len = bytes.put_varint(self.len().try_into().unwrap())?.len();
        bytes.put_bytes(self.crypto_data.as_ref())?;
        Ok(1 + off_len + data_len_len + self.len())
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

    fn to_bytes(
        &self,
        bytes: &mut octets::OctetsMut<'_>,
    ) -> Result<usize, octets::BufferTooShortError> {
        Ok(0)
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

    fn to_bytes(
        &self,
        bytes: &mut octets::OctetsMut<'_>,
    ) -> Result<usize, octets::BufferTooShortError> {
        Ok(0)
    }
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

    fn to_bytes(
        &self,
        bytes: &mut octets::OctetsMut<'_>,
    ) -> Result<usize, octets::BufferTooShortError> {
        Ok(0)
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

    fn to_bytes(
        &self,
        bytes: &mut octets::OctetsMut<'_>,
    ) -> Result<usize, octets::BufferTooShortError> {
        Ok(0)
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
            let token_length_length = match token.as_ref().unwrap().len() {
                0..=63 => 1,
                64..=16383 => 2,
                16384..=1073741823 => 3,
                _ => unreachable!("token size exceeded abnormally large size"),
            };

            raw_length += token_length_length + token.as_ref().unwrap().len();
        }

        //variable length packet length always encoded as length 4
        raw_length += 4;

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
        }
    }

    pub fn decrypt(
        &mut self,
        buffer: &mut [u8],
        header_key: &dyn HeaderProtectionKey,
    ) -> Result<usize, octets::BufferTooShortError> {
        let mut b = octets::OctetsMut::with_slice(buffer);
        b.skip(self.raw_length)?;

        let mut pn_and_sample = b.peek_bytes_mut(MAX_PKT_NUM_LEN as usize + SAMPLE_LEN)?;
        let (mut pn_cipher, sample) = pn_and_sample.split_at(MAX_PKT_NUM_LEN as usize)?;

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
    pub fn to_bytes(&self, b: &mut octets::OctetsMut) -> Result<(), octets::BufferTooShortError> {
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
            b.put_varint_with_len(self.length as u64, 4)?;
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
        b: &mut octets::OctetsMut,
        dcid_len: usize,
    ) -> Result<Header, octets::BufferTooShortError> {
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
                length: 0, //TODO
                raw_length: b.off(),
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
            }
            0x01 => (), // Zero-RTT
            0x02 => (), // Handshake
            0x03 => (), // Retry
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
        })
    }

    pub fn is_inital(&self) -> bool {
        ((self.hf & LS_TYPE_BIT) >> 7) == 1
    }

    pub fn calculate_pn_length(packet_number: u32) -> u8 {
        match packet_number {
            0x00..=0xff => 0,
            0x0100..=0xffff => 1,
            0x010000..=0xffffff => 2,
            0x01000000..=0xffffffff => 3,
        }
    }

    pub fn debug_print(&self) {
        println!(
            "{:#04x?} version: {:#06x?} pn: {:#010x?} dcid: 0x{} scid: 0x{} token:{:x?} length:{:?} raw_length:{:?}",
            ((self.hf & LONG_PACKET_TYPE) >> 4),
            self.version,
            self.packet_num,
            self.dcid
                .id
                .iter()
                .map(|val| format!("{:x}", val))
                .collect::<Vec<String>>()
                .join(""),
            self.scid
                .clone()
                .unwrap_or(ConnectionId::from_vec(Vec::new()))
                .id
                .iter()
                .map(|val| format!("{:x}", val))
                .collect::<Vec<String>>()
                .join(""),
            self.token.as_ref().unwrap(),
            self.length,
            self.raw_length,
        );
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
        let mut b = octets::OctetsMut::with_slice(&mut head_raw);

        let mut partial_decode = Header::from_bytes(&mut b, 8).unwrap();

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
        let ack = AckFrame::from_packet_number_vec(&pns);

        assert_eq!(ack.largest_acknowledged, 10);
        assert_eq!(ack.first_ack_range, 2);
        assert_eq!(ack.ack_range_count, 2);
        assert_eq!(ack.ack_ranges[0], (1, 2));
        assert_eq!(ack.ack_ranges[0], (1, 2));
    }

    #[test]
    fn test_ack_frame_creation_2() {
        let pns: Vec<u64> = vec![10, 9, 3, 2, 1, 0];
        let ack = AckFrame::from_packet_number_vec(&pns);

        assert_eq!(ack.largest_acknowledged, 10);
        assert_eq!(ack.first_ack_range, 1);
        assert_eq!(ack.ack_range_count, 1);
        assert_eq!(ack.ack_ranges[0], (5, 3));
    }

    #[test]
    fn test_long_initial_header_creation() {
        let dcid = ConnectionId::from_vec(vec![0x34, 0xa7, 0x84, 0xef, 0x34, 0xa7, 0x84, 0xef]);
        let scid = ConnectionId::from_vec(vec![0xd5, 0x85, 0x23, 0x1b, 0xd5, 0x85, 0x23, 0x1b]);
        let header = Header::new_long_header(0x00, 1, 0, &dcid, &scid, Some(vec![]), 1201).unwrap();

        let mut vec = vec![0u8; 29];

        let mut b = octets::OctetsMut::with_slice(&mut vec);

        header.to_bytes(&mut b).unwrap();

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

        header.to_bytes(&mut b).unwrap();

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

        header.to_bytes(&mut b).unwrap();

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

        header.to_bytes(&mut b).unwrap();

        let expected = vec![
            0x45, 0x34, 0xa7, 0x84, 0xef, 0x34, 0xa7, 0x84, 0xef, 0x01, 0x7c,
        ];

        assert_eq!(vec, expected);
        assert_eq!(header.raw_length, 9);
    }

    #[test]
    fn test_packet_builder_builds_initial_packet_with_minimum_size() {
        let dcid = ConnectionId::from_vec(vec![0x34, 0xa7, 0x84, 0xef, 0x34, 0xa7, 0x84, 0xef]);
        let scid = ConnectionId::from_vec(vec![0xd5, 0x85, 0x23, 0x1b, 0xd5, 0x85, 0x23, 0x1b]);

        let body = vec![
            0x06, 0x01, 0x00, 0x01, 0x03, 0x03, 0x03, 0x92, 0x2f, 0x01, 0x2b, 0xd7, 0x8b, 0x30,
            0xaa, 0xbd, 0xa6, 0x7c, 0x7a, 0x62, 0x75, 0xce, 0x4a, 0xbc, 0x3e, 0xd4, 0xa4, 0x23,
            0xe1, 0x03, 0xcc, 0xef, 0x4c, 0x9f, 0xcb, 0x28, 0xa4, 0x08, 0x97, 0x00, 0x00, 0x08,
            0x13, 0x02, 0x13, 0x01, 0x13, 0x03, 0x00, 0xff, 0x01, 0x00, 0x00, 0xd2, 0x00, 0x39,
        ];

        let mut result = vec![0u8; 2048];

        let pkb = PacketBuilder::new(1, &mut result);

        let (len, _) = pkb
            .with_body(body)
            .with_long_header(0x00, 0, &dcid, &scid, Some(vec![]))
            .unwrap()
            .encode()
            .unwrap();

        let mut expected: Vec<u8> = vec![
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x34, 0xa7, 0x84, 0xef, 0x34, 0xa7, 0x84, 0xef,
            0x08, 0xd5, 0x85, 0x23, 0x1b, 0xd5, 0x85, 0x23, 0x1b, 0x00, 0x80, 0x00, 0x04, 0x94,
            0x00, 0x06, 0x01, 0x00, 0x01, 0x03, 0x03, 0x03, 0x92, 0x2f, 0x01, 0x2b, 0xd7, 0x8b,
            0x30, 0xaa, 0xbd, 0xa6, 0x7c, 0x7a, 0x62, 0x75, 0xce, 0x4a, 0xbc, 0x3e, 0xd4, 0xa4,
            0x23, 0xe1, 0x03, 0xcc, 0xef, 0x4c, 0x9f, 0xcb, 0x28, 0xa4, 0x08, 0x97, 0x00, 0x00,
            0x08, 0x13, 0x02, 0x13, 0x01, 0x13, 0x03, 0x00, 0xff, 0x01, 0x00, 0x00, 0xd2, 0x00,
            0x39,
        ];
        expected.resize(1200, 0x00);

        assert_eq!(result[..len], expected);
    }

    #[test]
    fn test_coalesced_packet_building() {
        let dcid = ConnectionId::from_vec(vec![0x34, 0xa7, 0x84, 0xef, 0x34, 0xa7, 0x84, 0xef]);
        let scid = ConnectionId::from_vec(vec![0xd5, 0x85, 0x23, 0x1b, 0xd5, 0x85, 0x23, 0x1b]);
        let body = vec![
            0x06, 0x01, 0x00, 0x01, 0x03, 0x03, 0x03, 0x92, 0x2f, 0x01, 0x2b, 0xd7, 0x8b, 0x30,
            0xaa, 0xbd, 0xa6, 0x7c, 0x7a, 0x62, 0x75, 0xce, 0x4a, 0xbc, 0x3e, 0xd4, 0xa4, 0x23,
            0xe1, 0x03, 0xcc, 0xef, 0x4c, 0x9f, 0xcb, 0x28, 0xa4, 0x08, 0x97, 0x00, 0x00, 0x08,
            0x13, 0x02, 0x13, 0x01, 0x13, 0x03, 0x00, 0xff, 0x01, 0x00, 0x00, 0xd2, 0x00, 0x39,
        ];

        let mut result = vec![0u8; 4096];
        let mut offset = 0;

        let pkb1 = PacketBuilder::new(1, &mut result[offset..]);
        if let Ok((len1, _)) = pkb1
            .with_body(body.clone())
            .with_long_header(0x00, 0, &dcid, &scid, Some(vec![]))
            .unwrap()
            .encode()
        {
            offset += len1;
        }

        let pkb2 = PacketBuilder::new(1, &mut result[offset..]);
        if let Ok((len2, _)) = pkb2
            .with_body(body.clone())
            .with_long_header(0x00, 0, &dcid, &scid, Some(vec![]))
            .unwrap()
            .encode()
        {
            offset += len2;
        }

        let mut expected: Vec<u8> = vec![
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x34, 0xa7, 0x84, 0xef, 0x34, 0xa7, 0x84, 0xef,
            0x08, 0xd5, 0x85, 0x23, 0x1b, 0xd5, 0x85, 0x23, 0x1b, 0x00, 0x80, 0x00, 0x04, 0x94,
            0x00, 0x06, 0x01, 0x00, 0x01, 0x03, 0x03, 0x03, 0x92, 0x2f, 0x01, 0x2b, 0xd7, 0x8b,
            0x30, 0xaa, 0xbd, 0xa6, 0x7c, 0x7a, 0x62, 0x75, 0xce, 0x4a, 0xbc, 0x3e, 0xd4, 0xa4,
            0x23, 0xe1, 0x03, 0xcc, 0xef, 0x4c, 0x9f, 0xcb, 0x28, 0xa4, 0x08, 0x97, 0x00, 0x00,
            0x08, 0x13, 0x02, 0x13, 0x01, 0x13, 0x03, 0x00, 0xff, 0x01, 0x00, 0x00, 0xd2, 0x00,
            0x39,
        ];
        expected.resize(1200, 0x00);
        let mut second = expected.clone();
        expected.append(&mut second);

        assert_eq!(result[..offset], expected);
    }
}
