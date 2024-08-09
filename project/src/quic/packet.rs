use crate::{terror, token::StatelessResetToken, ConnectionId, TSDistributor};

use octets::Octets;
use rustls::quic::HeaderProtectionKey;

use std::{collections::VecDeque, marker::PhantomData, sync::Arc};

const MAX_PKT_NUM_LEN: usize = 4;
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

pub struct DatagramBuilder {
    dgram: Vec<u8>,
    packets: VecDeque<PacketBuilder<Completed>>,
    quic_version: u32,
    contains_initial: bool,
}

impl DatagramBuilder {
    pub fn new(quic_version: u32) -> Self {
        Self {
            dgram: vec![0u8; 65536],
            packets: VecDeque::new(),
            quic_version,
            contains_initial: false,
        }
    }

    pub fn add_packet(&mut self, packet: PacketBuilder<Completed>) {
        if packet.header.is_inital() {
            self.contains_initial = true;
        }

        assert!(self.quic_version == packet.quic_version);

        self.packets.push_back(packet);
    }

    pub fn build(mut self, address: String) -> Result<Datagram, terror::Error> {
        let mut offset: usize = 0;
        let size = self.packets.len();
        let mut dgram = std::mem::take(&mut self.dgram);
        let mut i: usize = 0;

        while let Some(mut packet) = self.packets.pop_front() {
            let tag_len = packet.keys.as_ref().unwrap().local.packet.tag_len();
            //add tag length to payload length
            packet.header.length += tag_len;

            //calculate required buffer length
            let mut required_space = packet.header.raw_length
                + packet.header.packet_num_length as usize
                + 1
                + packet.body.len()
                + tag_len;

            //check for minimum size if datagram contains initial packet
            if (i + 1) == size && self.contains_initial && (offset + required_space) < 1200 {
                let additional_space = 1200 - (offset + required_space);
                required_space += additional_space;
                packet.header.length += additional_space;
            }

            packet.encode_and_encrypt(&mut dgram[offset..offset + required_space])?;

            offset += required_space;
            i += 1;
        }

        dgram.resize(offset, 0x00);

        Ok((dgram, address))
    }
}

//Required for full packet
pub struct PacketBody;
pub struct PacketHeader;
pub struct PacketCrypto;
pub type Completed = (PacketBody, PacketHeader, PacketCrypto);

//Packet Builder
pub struct PacketBuilder<S = ((), (), ())> {
    keys: Option<Arc<rustls::quic::Keys>>,

    //packet
    header: Header,
    body: Vec<u8>,
    quic_version: u32,

    // required because we never use the zero-sized types
    phantom: PhantomData<S>,
}

// private to control how Thing can be constructed
fn new_packet_builder<S>(
    keys: Option<Arc<rustls::quic::Keys>>,
    header: Header,
    body: Vec<u8>,
    //packet_length: usize,
    quic_version: u32,
) -> PacketBuilder<S> {
    PacketBuilder {
        keys,
        header,
        body,
        quic_version,
        phantom: PhantomData,
    }
}

impl PacketBuilder {
    pub fn new(quic_version: u32) -> Self {
        new_packet_builder(None, Header::default(), Vec::new(), quic_version)
    }
}

impl<B, H, C> PacketBuilder<(B, H, C)> {
    pub fn with_body(self, body: Vec<u8>) -> PacketBuilder<(PacketBody, H, C)> {
        new_packet_builder(self.keys, self.header, body, self.quic_version)
    }

    pub fn with_long_header(
        self,
        long_header_type: u8,
        packet_number: u32,
        dcid: &ConnectionId,
        scid: &ConnectionId,
        token: Option<Vec<u8>>,
    ) -> Result<PacketBuilder<(B, PacketHeader, C)>, terror::Error> {
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
            self.keys,
            header,
            self.body,
            self.quic_version,
        ))
    }

    pub fn with_short_header(
        self,
        packet_number: u32,
        dcid: &ConnectionId,
        spin_bit: u8,
        key_phase: u8,
    ) -> Result<PacketBuilder<(B, PacketHeader, C)>, terror::Error> {
        let header =
            Header::new_short_header(spin_bit, key_phase, self.quic_version, packet_number, dcid)?;

        Ok(new_packet_builder(
            self.keys,
            header,
            self.body,
            self.quic_version,
        ))
    }

    pub fn with_crypto(self, keys: Arc<rustls::quic::Keys>) -> PacketBuilder<(B, H, PacketCrypto)> {
        new_packet_builder(Some(keys), self.header, self.body, self.quic_version)
    }
}

impl<C> PacketBuilder<(PacketBody, PacketHeader, C)> {
    // encodes the packet and its header into the datagram, can only be called after body and
    // header have been specified
    fn encode(&self, dgram: &mut [u8]) -> Result<(), terror::Error> {
        println!("AVAILIBLE SPACE: {:?}", dgram.len());

        let mut b = octets::OctetsMut::with_slice(dgram);

        self.header.debug_print();

        //encode header
        if let Err(err) = self.header.to_bytes(&mut b) {
            return Err(terror::Error::buffer_size_error(format!(
                "Fatal error while encoding header: {}",
                err
            )));
        }

        //encode body
        if let Err(err) = b.put_bytes(&self.body) {
            return Err(terror::Error::buffer_size_error(format!(
                "Fatal error while encoding packet body: {}",
                err
            )));
        }

        Ok(())
    }
}

impl PacketBuilder<Completed> {
    fn encode_and_encrypt(self, packet: &mut [u8]) -> Result<(), terror::Error> {
        self.encode(packet)?;
        self.encrypt(packet)?;
        Ok(())
    }

    //encrypts the packet in dgram and consumes self, finalizing the packet
    fn encrypt(self, packet: &mut [u8]) -> Result<(), terror::Error> {
        let keys = self.keys.unwrap();

        let tag_len = keys.local.packet.tag_len();

        let header_end_off: usize =
            self.header.raw_length + self.header.packet_num_length as usize + 1;

        //encrypts the packet payload and copies the tag into the buffer
        let (header, payload_tag) = packet.split_at_mut(header_end_off);

        let (payload, tag_storage) = payload_tag.split_at_mut(payload_tag.len() - tag_len);
        let tag = keys
            .local
            .packet
            .encrypt_in_place(self.header.packet_num as u64, &*header, payload)
            .unwrap();

        tag_storage.copy_from_slice(tag.as_ref());

        //encrypts the header
        let pn_offset = header_end_off - (self.header.packet_num_length as usize + 1);
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
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

        Ok(())
    }
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
    //generates an ack frame from a vector of packet numbers. The vector has to be sorted in
    //descending order, i.e. the highest packet number has to be at index 0.
    pub fn from_packet_number_vec(packet_numbers: &[u64], ack_delay: u64) -> Self {
        let mut ack = Self::empty(ack_delay);
        ack.len = 1;
        println!("len + 1 from frame code");
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

        ack.len += varint_length(ack.largest_acknowledged)
            + varint_length(ack.ack_delay)
            + varint_length(ack.ack_range_count)
            + varint_length(ack.first_ack_range);

        println!(
            "len + {:?} from la",
            varint_length(ack.largest_acknowledged)
        );
        println!("len + {:?} from ad", varint_length(ack.ack_delay));
        println!("len + {:?} from arc", varint_length(ack.ack_range_count));
        println!("len + {:?} from far", varint_length(ack.first_ack_range));

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

        println!("len + {:?} from gap", varint_length(gap));
        println!("len + {:?} from range", varint_length(range));
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

pub struct StreamFrame {
    pub(crate) stream_id: u64,
    pub(crate) offset: Option<u64>,
    pub(crate) length: Option<u64>,
    pub(crate) fin_bit_set: bool,
    pub(crate) len: usize,
}

impl Frame for StreamFrame {
    fn from_bytes(frame_code: &u8, bytes: &mut octets::OctetsMut<'_>) -> Self {
        let begin = bytes.off() - 1;
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
    len: usize,
}

impl Frame for NewConnectionIdFrame {
    fn from_bytes(frame_code: &u8, bytes: &mut octets::OctetsMut<'_>) -> Self {
        let begin = bytes.off() - 1;
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
            let token_length_length = varint_length(token.as_ref().unwrap().len() as u64);

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
        // b: &mut octets::OctetsMut,
        buffer: &[u8],
        dcid_len: usize,
    ) -> Result<Header, octets::BufferTooShortError> {
        let mut b = Octets::with_slice(buffer);
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
            self.token.as_ref().unwrap_or(&vec![0u8; 0]),
            self.length,
            self.raw_length,
        );
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
    fn test_packet_builder_encodes_initial_packet() {
        let dcid = ConnectionId::from_vec(vec![0x34, 0xa7, 0x84, 0xef, 0x34, 0xa7, 0x84, 0xef]);
        let scid = ConnectionId::from_vec(vec![0xd5, 0x85, 0x23, 0x1b, 0xd5, 0x85, 0x23, 0x1b]);

        let body = vec![
            0x06, 0x01, 0x00, 0x01, 0x03, 0x03, 0x03, 0x92, 0x2f, 0x01, 0x2b, 0xd7, 0x8b, 0x30,
            0xaa, 0xbd, 0xa6, 0x7c, 0x7a, 0x62, 0x75, 0xce, 0x4a, 0xbc, 0x3e, 0xd4, 0xa4, 0x23,
            0xe1, 0x03, 0xcc, 0xef, 0x4c, 0x9f, 0xcb, 0x28, 0xa4, 0x08, 0x97, 0x00, 0x00, 0x08,
            0x13, 0x02, 0x13, 0x01, 0x13, 0x03, 0x00, 0xff, 0x01, 0x00, 0x00, 0xd2, 0x00, 0x39,
        ];

        let mut result = vec![0u8; 2048];

        let pkb = PacketBuilder::new(1);

        pkb.with_body(body)
            .with_long_header(0x00, 0, &dcid, &scid, Some(vec![]))
            .unwrap()
            .encode(&mut result)
            .unwrap();

        let expected: Vec<u8> = vec![
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x34, 0xa7, 0x84, 0xef, 0x34, 0xa7, 0x84, 0xef,
            0x08, 0xd5, 0x85, 0x23, 0x1b, 0xd5, 0x85, 0x23, 0x1b, 0x00, 0x80, 0x00, 0x00, 0x39,
            0x00, 0x06, 0x01, 0x00, 0x01, 0x03, 0x03, 0x03, 0x92, 0x2f, 0x01, 0x2b, 0xd7, 0x8b,
            0x30, 0xaa, 0xbd, 0xa6, 0x7c, 0x7a, 0x62, 0x75, 0xce, 0x4a, 0xbc, 0x3e, 0xd4, 0xa4,
            0x23, 0xe1, 0x03, 0xcc, 0xef, 0x4c, 0x9f, 0xcb, 0x28, 0xa4, 0x08, 0x97, 0x00, 0x00,
            0x08, 0x13, 0x02, 0x13, 0x01, 0x13, 0x03, 0x00, 0xff, 0x01, 0x00, 0x00, 0xd2, 0x00,
            0x39,
        ];

        assert_eq!(result[..expected.len()], expected);
    }

    #[test]
    fn test_coalesced_packet_datagram_building() {}
}
