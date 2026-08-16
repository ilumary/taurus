use crate::{cid, ranges::RangeSet, terror, SPACE_ID_DATA, SPACE_ID_HANDSHAKE, SPACE_ID_INITIAL};

use octets::{Octets, OctetsMut};
use rustls::quic::{DirectionalKeys, HeaderProtectionKey};

use std::{fmt, ops::RangeInclusive};

const MAX_PKT_NUM_LEN: usize = 4;
const SAMPLE_LEN: usize = 16;
pub const PACKET_LENGTH_ENCODING_LENGTH: usize = 4;

pub const LS_TYPE_BIT: u8 = 0x80;
pub const LONG_PACKET_TYPE: u8 = 0x30;
const PKT_NUM_LENGTH_MASK: u8 = 0x03;

pub const LONG_HEADER_TYPE_INITIAL: u8 = 0x00;
pub const LONG_HEADER_TYPE_HANDSHAKE: u8 = 0x02;

//encrypts a packet, pn_len is in bytes starting at one and header_end_off must include packet number
pub fn encrypt(
    packet: &mut OctetsMut,
    keys: &DirectionalKeys,
    pn: u64,
    payload_offset: usize,
) -> Result<usize, terror::Error> {
    let tag_len = keys.packet.tag_len();
    let packet_length = packet.off() + tag_len;

    //println!("packet pre encrypt: {:x?}", &packet.buf()[..packet_length]);

    let (mut p, _) = packet.split_at(packet_length)?;

    let pn_len = Header::calculate_pn_length(pn as u32) as usize + 1;

    //encrypts the packet payload and copies the tag into the buffer
    let (mut header, mut payload_and_tag) = p.split_at(payload_offset)?;

    let (mut payload, mut tag_storage) =
        payload_and_tag.split_at(payload_and_tag.len() - tag_len)?;
    let tag = keys
        .packet
        .encrypt_in_place(pn, header.as_mut(), payload.as_mut())
        .unwrap();

    //println!("tag: {:x?}", tag.as_ref());

    tag_storage.put_bytes(tag.as_ref())?;

    //encrypts the header
    let pn_offset = payload_offset - pn_len;
    let (mut header, sample) = p.split_at(pn_offset + 4)?;
    let (mut first, mut rest) = header.split_at(1)?;
    let pn_end = Ord::min(pn_offset + 3, rest.len());

    let sample_offset = pn_offset + 4;
    if sample_offset + keys.header.sample_len() > packet_length {
        return Err(terror::Error::buffer_size_error(
            "packet too short to sample for header protection",
        ));
    }

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

pub struct AckFrame {
    ranges: Vec<RangeInclusive<u64>>,
    ack_delay: u64,

    //for ack type 0x03 ack frame contains ecn counts, rfc 9000 19.3.2
    ecn_counts: Option<(u64, u64, u64)>,
}

impl AckFrame {
    /// parses an [`AckFrame`] from raw bytes
    pub fn parse(frame_code: &u8, bytes: &mut octets::OctetsMut<'_>) -> Self {
        let largest = bytes.get_varint().unwrap();
        let ack_delay = bytes.get_varint().unwrap();
        let ack_range_count = bytes.get_varint().unwrap();
        let first_ack_range = bytes.get_varint().unwrap();

        let mut ranges = Vec::with_capacity(1 + ack_range_count as usize);
        ranges.push((largest - first_ack_range)..=largest);

        let mut prev_smallest = largest - first_ack_range;

        for _ in 0..ack_range_count {
            let gap = bytes.get_varint().unwrap();
            let ack_range = bytes.get_varint().unwrap();
            let end = prev_smallest - gap - 2;
            let start = end - ack_range;
            ranges.push(start..=end);
            prev_smallest = start;
        }

        let ecn_counts = if *frame_code == 0x03 {
            Some((
                bytes.get_varint().unwrap(),
                bytes.get_varint().unwrap(),
                bytes.get_varint().unwrap(),
            ))
        } else {
            None
        };

        AckFrame {
            ranges,
            ack_delay,
            ecn_counts,
        }
    }

    /// serialize an [`AckFrame`] directly from a [`RangeSet`]
    pub fn to_bytes(
        rs: &RangeSet,
        ecn_counts: Option<(u64, u64, u64)>,
        ack_delay: u64,
        out: &mut octets::OctetsMut<'_>,
    ) -> Result<usize, octets::BufferTooShortError> {
        let begin = out.off();
        let frame_type: u64 = if ecn_counts.is_some() { 0x03 } else { 0x02 };

        let mut ranges = rs.iter().rev();

        let top = ranges.next().expect("non-empty checked above");
        let largest = *top.end();
        let first_ack_range = largest - *top.start();

        out.put_varint(frame_type)?;
        out.put_varint(largest)?;
        out.put_varint(ack_delay)?;
        out.put_varint(rs.num_ranges() as u64 - 1)?; // ack_range_count
        out.put_varint(first_ack_range)?;

        let mut prev_smallest = *top.start();
        for r in ranges {
            let end = *r.end();
            let start = *r.start();
            let gap = prev_smallest - end - 2;
            let ack_range = end - start;
            out.put_varint(gap)?;
            out.put_varint(ack_range)?;
            prev_smallest = start;
        }

        if let Some((ect0, ect1, ecn_ce)) = ecn_counts {
            out.put_varint(ect0)?;
            out.put_varint(ect1)?;
            out.put_varint(ecn_ce)?;
        }

        Ok(out.off() - begin)
    }

    /// return the largest acknowledged packet number
    pub fn largest_acknowledged(&self) -> u64 {
        *self.ranges[0].end()
    }

    /// returns the ack ranges of the [AckFrame]
    pub fn ranges(&self) -> &[RangeInclusive<u64>] {
        &self.ranges
    }

    /// returns the ack delay of the [AckFrame]
    pub fn ack_delay(&self) -> u64 {
        self.ack_delay
    }
}

/// QUIC header
pub struct Header {
    /// header form and version specific bits
    pub hf: u8,

    /// QUIC version
    pub version: u32,

    /// destination connection id
    pub dcid: cid::Id,

    /// source connection id, absent if short
    pub scid: Option<cid::Id>,

    /// byte range of the token within the packet buffer
    pub token: Option<core::ops::Range<usize>>,

    /// packet number
    pub packet_num: u64,

    /// packet numbet length
    pub packet_num_length: u8,

    /// encoded payload length
    pub length: usize,

    /// wire length of packet
    pub raw_length: usize,

    /// space this packet belongs to
    space: usize,
}

impl Header {
    /// peeks dcid as fast as possible for incoming path
    pub fn peek_dcid(buf: &[u8], local_cid_len: usize) -> Result<&[u8], terror::Error> {
        let mut b = Octets::with_slice(buf);
        let hf = b.get_u8()?;
        let len = if (hf & LS_TYPE_BIT) == 0 {
            local_cid_len
        } else {
            b.get_u32()?;
            let l = b.get_u8()? as usize;
            if l > cid::MAX_CID_SIZE {
                return Err(terror::Error::quic_transport_error(
                    "dcid longer than 20 bytes",
                    terror::QuicTransportError::ProtocolViolation,
                ));
            }
            l
        };
        Ok(b.get_bytes(len)?.buf())
    }

    /// parses a header from raw byte slice
    pub fn from_bytes(buffer: &[u8], dcid_len: usize) -> Result<Header, terror::Error> {
        let mut b = Octets::with_slice(buffer);
        let hf = b.get_u8()?;

        if (hf & LS_TYPE_BIT) == 0 {
            let dcid = b.get_bytes(dcid_len)?;
            return Ok(Header {
                hf,
                version: 0,
                dcid: cid::Id::from_slice(dcid.buf()),
                scid: None,
                token: None,
                packet_num: 0,
                packet_num_length: 0,
                length: 0,
                raw_length: b.off(),
                space: SPACE_ID_DATA,
            });
        }

        let version = b.get_u32()?;

        let dcid_length = b.get_u8()? as usize;
        if dcid_length > cid::MAX_CID_SIZE {
            return Err(terror::Error::quic_transport_error(
                "dcid longer than 20 bytes",
                terror::QuicTransportError::ProtocolViolation,
            ));
        }
        let dcid = cid::Id::from_slice(b.get_bytes(dcid_length)?.buf());

        let scid_length = b.get_u8()? as usize;
        if scid_length > cid::MAX_CID_SIZE {
            return Err(terror::Error::quic_transport_error(
                "scid longer than 20 bytes",
                terror::QuicTransportError::ProtocolViolation,
            ));
        }
        let scid = cid::Id::from_slice(b.get_bytes(scid_length)?.buf());

        let mut token = None;
        let mut space = SPACE_ID_DATA;

        match (hf & LONG_PACKET_TYPE) >> 4 {
            0x00 => {
                // Initial
                let tl = b.get_varint()? as usize;
                let start = b.off();
                b.skip(tl)?;
                token = Some(start..start + tl);
                space = SPACE_ID_INITIAL;
            }
            0x01 => {}                          // 0-RTT
            0x02 => space = SPACE_ID_HANDSHAKE, // Handshake
            0x03 => {
                // Retry
                return Ok(Header {
                    hf,
                    version,
                    dcid,
                    scid: Some(scid),
                    token: None,
                    packet_num: 0,
                    packet_num_length: 0,
                    length: 0,
                    raw_length: b.off(),
                    space: SPACE_ID_INITIAL,
                });
            }
            _ => unreachable!("2-bit long packet type"),
        }

        let length = b.get_varint()? as usize;

        Ok(Header {
            hf,
            version,
            dcid,
            scid: Some(scid),
            token,
            packet_num: 0,
            packet_num_length: 0,
            length,
            raw_length: b.off(),
            space,
        })
    }

    /// calculates wire length of long header
    pub fn long_header_len(
        long_header_type: u8,
        dcid: &cid::Id,
        scid: &cid::Id,
        token: Option<&[u8]>,
        packet_num: u64,
    ) -> usize {
        let mut n = 1 + 4 + 1 + dcid.len() + 1 + scid.len();
        if long_header_type == LONG_HEADER_TYPE_INITIAL {
            let tl = token.map_or(0, |t| t.len());
            n += octets::varint_len(tl as u64) + tl;
        }
        n + PACKET_LENGTH_ENCODING_LENGTH
            + Self::calculate_pn_length(packet_num as u32) as usize
            + 1
    }

    /// calculates wire length of short header
    #[inline]
    pub fn short_header_len(dcid: &cid::Id, packet_num: u64) -> usize {
        1 + dcid.len() + Self::calculate_pn_length(packet_num as u32) as usize + 1
    }

    #[inline]
    fn put_pn(b: &mut OctetsMut, pn: u64, pn_length: u8) -> Result<(), terror::Error> {
        match pn_length {
            0 => b.put_u8(pn as u8)?,
            1 => b.put_u16(pn as u16)?,
            2 => b.put_u24(pn as u32)?,
            3 => b.put_u32(pn as u32)?,
            _ => unreachable!("pn length is 2 bits"),
        };
        Ok(())
    }

    fn header_byte(long: bool, spin_bit: u8, lht: u8, key_phase: u8, pn_length: u8) -> u8 {
        let mut hf = 0u8;
        hf |= (long as u8) << 7;
        hf |= 1 << 6;
        hf |= spin_bit << 5;
        hf |= lht << 4;
        hf |= key_phase << 2;
        hf |= pn_length;
        hf
    }

    pub fn encode_long(
        b: &mut OctetsMut,
        long_header_type: u8,
        version: u32,
        dcid: &cid::Id,
        scid: &cid::Id,
        token: Option<&[u8]>,
        packet_num: u64,
    ) -> Result<(u8, Option<usize>), terror::Error> {
        debug_assert!(matches!(long_header_type, 0x00..=0x03));
        let pn_length = Self::calculate_pn_length(packet_num as u32);

        b.put_u8(Self::header_byte(true, 0, long_header_type, 0, pn_length))?;
        b.put_u32(version)?;
        b.put_u8(dcid.len() as u8)?;
        b.put_bytes(dcid.as_slice())?;
        b.put_u8(scid.len() as u8)?;
        b.put_bytes(scid.as_slice())?;

        if long_header_type == LONG_HEADER_TYPE_INITIAL {
            match token {
                Some(t) => {
                    b.put_varint(t.len() as u64)?;
                    b.put_bytes(t)?;
                }
                None => {
                    b.put_varint(0)?;
                }
            }
        }

        let length_field_offset = b.off();
        b.put_varint_with_len(0, PACKET_LENGTH_ENCODING_LENGTH)?; // placeholder
        Self::put_pn(b, packet_num, pn_length)?;

        Ok((pn_length, Some(length_field_offset)))
    }

    pub fn encode_short(
        b: &mut OctetsMut,
        spin_bit: u8,
        key_phase: u8,
        dcid: &cid::Id,
        packet_num: u64,
    ) -> Result<(u8, Option<usize>), terror::Error> {
        let pn_length = Self::calculate_pn_length(packet_num as u32);
        b.put_u8(Self::header_byte(false, spin_bit, 0, key_phase, pn_length))?;
        b.put_bytes(dcid.as_slice())?;
        Self::put_pn(b, packet_num, pn_length)?;
        Ok((pn_length, None))
    }

    pub fn patch_length(
        b: &mut OctetsMut,
        length_field_offset: usize,
        length: usize,
    ) -> Result<(), terror::Error> {
        let (_, mut l) = b.split_at(length_field_offset)?;
        l.put_varint_with_len(length as u64, PACKET_LENGTH_ENCODING_LENGTH)?;
        Ok(())
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
            0 => u64::from(b.get_u8()?),
            1 => u64::from(b.get_u16()?),
            2 => b.get_u24()? as u64,
            3 => b.get_u32()? as u64,
            _ => return Err(octets::BufferTooShortError),
        };

        Ok(self.raw_length + self.packet_num_length as usize + 1)
    }

    #[inline]
    pub fn token<'a>(&self, packet: &'a [u8]) -> Option<&'a [u8]> {
        self.token.clone().map(|r| &packet[r])
    }

    pub fn space(&self) -> usize {
        self.space
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

impl core::fmt::Display for Header {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let token = match &self.token {
            Some(r) => r.len(),
            None => 0,
        };
        match (self.hf & LS_TYPE_BIT) >> 7 {
            0 => write!(
                f,
                "SH {:#b} version:{:#06x?} pn:{:#010x?} dcid:{} raw_length:{}",
                self.hf, self.version, self.packet_num, self.dcid, self.raw_length
            ),
            1 => write!(
                f,
                "[LH] {:#b} version:{:#06x?} pn:{:#010x?} dcid:{} scid:{} token:{}B length:{} raw_length:{}",
                self.hf,
                self.version,
                self.packet_num,
                self.dcid,
                self.scid.as_ref().map(|c| c.to_string()).unwrap_or_default(),
                token,
                self.length,
                self.raw_length
            ),
            _ => unreachable!("you just broke the laws of physics"),
        }
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
    #[inline]
    fn from(pt: PacketType) -> String {
        match pt {
            PacketType::None => "N".to_string(),
            PacketType::Initial => "I".to_string(),
            PacketType::ZeroRtt => "Z".to_string(),
            PacketType::Handshake => "H".to_string(),
            PacketType::Retry => "R".to_string(),
            PacketType::Short => "S".to_string(),
        }
    }
}

impl fmt::Display for PacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from(*self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(bytes: &[u8]) -> cid::Id {
        cid::Id::from_slice(bytes)
    }

    // encode header, write a payload, patch length
    fn encode_initial(
        dcid: &cid::Id,
        scid: &cid::Id,
        token: Option<&[u8]>,
        pn: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut back = vec![0u8; 256];
        let (meta, hdr_end, len_field);
        {
            let mut b = OctetsMut::with_slice(&mut back);
            meta = Header::encode_long(&mut b, LONG_HEADER_TYPE_INITIAL, 1, dcid, scid, token, pn)
                .unwrap();
            hdr_end = b.off();
            len_field = meta.1.unwrap();
            b.put_bytes(payload).unwrap();
            let total = back.len();
            let mut b2 = OctetsMut::with_slice(&mut back[..total]);
            // length covers pn + payload (no AEAD tag here)
            let length = payload.len() + meta.0 as usize + 1;
            Header::patch_length(&mut b2, len_field, length).unwrap();
        }
        let _ = hdr_end;
        back
    }

    #[test]
    fn long_header_len_matches_encoded_offset() {
        let dcid = id(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let scid = id(&[9, 10, 11, 12]);
        let token = &[0xAAu8; 17][..];
        let mut back = vec![0u8; 128];
        let end = {
            let mut b = OctetsMut::with_slice(&mut back);
            Header::encode_long(
                &mut b,
                LONG_HEADER_TYPE_INITIAL,
                1,
                &dcid,
                &scid,
                Some(token),
                300,
            )
            .unwrap();
            b.off()
        };
        assert_eq!(
            end,
            Header::long_header_len(LONG_HEADER_TYPE_INITIAL, &dcid, &scid, Some(token), 300)
        );
    }

    #[test]
    fn token_encode() {
        let dcid = id(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let scid = id(&[9, 10, 11, 12, 13, 14, 15, 16]);
        let pkt = encode_initial(&dcid, &scid, None, 5, &[0xDE, 0xAD]);
        let parsed = Header::from_bytes(&pkt, 8).unwrap();

        assert_eq!(parsed.token(&pkt), Some(&[][..]));
        assert_eq!(parsed.space(), SPACE_ID_INITIAL);
        assert_eq!(parsed.dcid, dcid);
        assert_eq!(parsed.scid, Some(scid));

        let pkt = encode_initial(&dcid, &scid, Some(&[0u8]), 5, &[0xDE, 0xAD]);
        let parsed = Header::from_bytes(&pkt, 8).unwrap();
        assert_eq!(parsed.token(&pkt), Some(&[0u8][..]));
    }

    #[test]
    fn token_borrow_not_copy() {
        let dcid = id(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let scid = id(&[9, 10, 11, 12, 13, 14, 15, 16]);
        let token = &[0x11u8, 0x22, 0x33, 0x44, 0x55][..];
        let pkt = encode_initial(&dcid, &scid, Some(token), 5, &[0xDE, 0xAD]);
        let parsed = Header::from_bytes(&pkt, 8).unwrap();

        let borrowed = parsed.token(&pkt).unwrap();
        assert_eq!(borrowed, token);
        let range = parsed.token.clone().unwrap();
        assert_eq!(&pkt[range], token);
    }

    #[test]
    fn peek_dcid() {
        let dcid = id(&[7, 7, 7, 7, 7, 7, 7, 7]);
        let scid = id(&[8, 8, 8, 8]);
        let pkt = encode_initial(&dcid, &scid, None, 1, &[0x00]);
        assert_eq!(Header::peek_dcid(&pkt, 8).unwrap(), dcid.as_slice());
        assert_eq!(
            Header::peek_dcid(&pkt, 8).unwrap(),
            Header::from_bytes(&pkt, 8).unwrap().dcid.as_slice()
        );

        // short header: dcid length is not on the wire, caller supplies it
        let mut back = vec![0u8; 64];
        {
            let mut b = OctetsMut::with_slice(&mut back);
            Header::encode_short(&mut b, 0, 0, &dcid, 9).unwrap();
        }
        assert_eq!(Header::peek_dcid(&back, 8).unwrap(), dcid.as_slice());
    }

    #[test]
    fn short_header_roundtrip() {
        let dcid = id(&[3, 1, 4, 1, 5, 9, 2, 6]);
        let mut back = vec![0u8; 64];
        let meta = {
            let mut b = OctetsMut::with_slice(&mut back);
            Header::encode_short(&mut b, 1, 0, &dcid, 0x0102).unwrap()
        };
        assert!(meta.1.is_none());
        assert_eq!(meta.0, 1); // 0x0102 needs two bytes
        let parsed = Header::from_bytes(&back, 8).unwrap();
        assert_eq!(parsed.space(), SPACE_ID_DATA);
        assert_eq!(parsed.dcid, dcid);
        assert!(parsed.scid.is_none());
    }

    #[test]
    fn handshake_header_carries_no_token_field() {
        let dcid = id(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let scid = id(&[9, 10, 11, 12]);
        let mut back = vec![0u8; 128];
        let len_field = {
            let mut b = OctetsMut::with_slice(&mut back);
            let m =
                Header::encode_long(&mut b, LONG_HEADER_TYPE_HANDSHAKE, 1, &dcid, &scid, None, 2)
                    .unwrap();
            b.put_bytes(&[0xAB, 0xCD]).unwrap();
            m.1.unwrap()
        };
        Header::patch_length(&mut OctetsMut::with_slice(&mut back), len_field, 2 + 1).unwrap();
        let parsed = Header::from_bytes(&back, 8).unwrap();
        assert_eq!(parsed.space(), SPACE_ID_HANDSHAKE);
        assert!(parsed.token.is_none());
    }

    #[test]
    fn ack_frame_encodes_and_decodes_without_ecn_conuts() {
        let mut r = RangeSet::new(64);
        r.insert(0..=10);
        r.insert(15..=25);

        let mut buf = vec![0u8; 256];
        let mut out = octets::OctetsMut::with_slice(&mut buf);

        let n = AckFrame::to_bytes(&r, None, 2000, &mut out);
        assert!(n.is_ok());
        let n = n.unwrap();

        let mut oct = octets::OctetsMut::with_slice(&mut buf[..n]);
        let t = oct.get_varint().unwrap() as u8;
        let f = AckFrame::parse(&t, &mut oct);

        assert_eq!(t, 0x02);
        assert_eq!(f.ranges.len(), 2);
        assert_eq!(f.ranges[1], (0..=10));
        assert_eq!(f.ranges[0], (15..=25));
        assert_eq!(f.ack_delay, 2000);
        assert_eq!(f.ecn_counts, None);
    }

    #[test]
    fn ack_frame_encodes_and_decodes_with_ecn_conuts() {
        let mut r = RangeSet::new(64);
        r.insert(0..=10);
        r.insert(15..=25);

        let mut buf = vec![0u8; 256];
        let mut out = octets::OctetsMut::with_slice(&mut buf);

        let n = AckFrame::to_bytes(&r, Some((1u64, 2u64, 3u64)), 2000, &mut out);
        assert!(n.is_ok());
        let n = n.unwrap();

        let mut oct = octets::OctetsMut::with_slice(&mut buf[..n]);
        let t = oct.get_varint().unwrap() as u8;
        let f = AckFrame::parse(&t, &mut oct);

        assert_eq!(t, 0x03);
        assert_eq!(f.ranges.len(), 2);
        assert_eq!(f.ranges[1], (0..=10));
        assert_eq!(f.ranges[0], (15..=25));
        assert_eq!(f.ack_delay, 2000);
        assert_eq!(f.ecn_counts, Some((1, 2, 3)));
    }
}
