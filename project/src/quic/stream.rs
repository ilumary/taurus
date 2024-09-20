use crate::{terror, Connection};

use std::{collections::VecDeque, future, ops::Range, sync::Arc};

use indexmap::IndexMap;
use tracing::{debug, warn};

const STREAM_TYPE: u64 = 0x3;
const CLIENT_INIT_BIDI: u64 = 0x00;
const SERVER_INIT_BIDI: u64 = 0x01;
const CLIENT_INIT_UNI: u64 = 0x02;
const SERVER_INIT_UNI: u64 = 0x03;

type StreamId = u64;

// public struct for the RecvStream, maybe also add reference to actual stream object to save on
// search in indexmap
pub struct RecvStream {
    id: StreamId,
    inner: Connection,
}

impl RecvStream {
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, terror::Error> {
        future::poll_fn(|cx| self.inner.api.poll_recv(cx, &self.id, buf)).await
    }
}

// public struct for the SendStream
pub struct SendStream {
    id: StreamId,
    inner: Connection,
}

impl SendStream {
    pub async fn write(&self, buf: &[u8]) -> Result<usize, terror::Error> {
        future::poll_fn(|cx| self.inner.api.poll_send(cx, &self.id, buf)).await
    }
}

// stores and manages streams for connection
// TODO register callback on recv stream
// TODO initialize with limits
pub struct StreamManager {
    // all streams, sorted by inbound and outbound
    outbound: IndexMap<StreamId, SendStreamInner>,
    inbound: IndexMap<StreamId, RecvStreamInner>,

    // [client init bidi, server init bidi, client init uni, server init uni]
    counts: [u64; 4],

    // used as least significant bit in stream ids. distinguishes between client (0x00) and server
    // (0x01)
    local: u8,
}

impl StreamManager {
    pub fn new(local: u8) -> Self {
        assert!(local == 0x00 || local == 0x01, "local must be 0x00 or 0x01");

        Self {
            inbound: IndexMap::new(),
            outbound: IndexMap::new(),
            counts: [0, 0, 0, 0],
            local,
        }
    }

    // creates a new stream with a given stream id
    fn create(&mut self, stream_id: StreamId, local: bool) -> Result<(), terror::Error> {
        if self.inbound.contains_key(&stream_id) || self.outbound.contains_key(&stream_id) {
            return Err(terror::Error::stream_error("stream does already exist"));
        }

        let stream_t = stream_id & STREAM_TYPE;
        let sequence = stream_id >> 2;

        if sequence >= self.counts[stream_t as usize] {
            self.counts[stream_t as usize] = sequence + 1;
        }

        if stream_t == CLIENT_INIT_BIDI || stream_t == SERVER_INIT_BIDI {
            self.inbound.insert(stream_id, RecvStreamInner::new());
            self.outbound.insert(stream_id, SendStreamInner::new());
        } else if (stream_t == CLIENT_INIT_UNI || stream_t == SERVER_INIT_UNI) && local {
            // if stream is unidirectional and created locally it is always outbound
            self.outbound.insert(stream_id, SendStreamInner::new());
        } else if (stream_t == CLIENT_INIT_UNI || stream_t == SERVER_INIT_UNI) && !local {
            // if it is not locally created it must be inbound
            self.inbound.insert(stream_id, RecvStreamInner::new());
        }

        Ok(())
    }

    // issues a new stream id and creates a new stream
    // TODO check local stream limits
    pub fn initiate(&mut self, bidi: bool) -> Result<StreamId, terror::Error> {
        // issue new stream id, start with locality
        let mut id = self.local as u64;

        // a bit of parsing to add bidirectionality to id
        id |= (!bidi as u64) << 1;

        // now add sequence number aka the inner id
        id |= self.counts[id as usize] << 2;

        self.create(id, true)?;

        debug!("initiated new stream with id: {}", id);

        Ok(id)
    }

    //TODO check stream limits
    pub fn incoming(
        &mut self,
        stream_id: u64,
        offset: u64,
        length: u64,
        fin: bool,
        data: &[u8],
    ) -> Result<(), terror::Error> {
        if let Some(rs) = self.inbound.get_mut(&stream_id) {
            return rs.process(offset, length, fin, data);
        }

        if (stream_id & 0x01) == self.local as u64 {
            return Err(terror::Error::stream_error("local stream cant be incoming"));
        }

        // because stream is incoming it cant be local
        self.create(stream_id, false)?;

        debug!(
            "created new stream with id {} from incoming frame",
            stream_id
        );

        //unwrap is safe because stream was created
        let recv_s = self.inbound.get_mut(&stream_id).unwrap();
        recv_s.process(offset, length, fin, data)?;

        Ok(())
    }

    // Appends to an existing outbound stream. Because we can only append to send streams
    // which must either have been created as local unidirectional stream or as incoming
    // bidirectional stream, we return an error if send stream could not found.
    pub fn append(
        &mut self,
        stream_id: StreamId,
        data: &[u8],
        fin: bool,
    ) -> Result<(), terror::Error> {
        if let Some(ss) = self.outbound.get_mut(&stream_id) {
            return ss.append(data, fin);
        }

        Err(terror::Error::stream_error(format!(
            "send stream with id {} no found",
            stream_id
        )))
    }

    // resets any given stream_id. If a receiving stream is reset, a final size must be supplied
    pub fn reset(
        &mut self,
        stream_id: u64,
        apec: u64,
        final_size: Option<u64>,
    ) -> Result<(), terror::Error> {
        if let Some(rs) = self.inbound.get_mut(&stream_id) {
            rs.reset(apec, final_size.unwrap())?;
        }

        if let Some(ss) = self.outbound.get_mut(&stream_id) {
            ss.reset(apec)?;
        }

        Ok(())
    }
}

//TODO retransmits
struct SendStreamInner {
    //data chunks ordered in outgoing direction
    data: VecDeque<Chunk>,

    //keeps track of pending stream data via packet number
    pending: IndexMap<u64, Chunk>,

    //current highest offset
    next_off: u64,

    //holds final size if known
    final_size: Option<usize>,

    //application error code in case stream is reset
    apec: Option<u64>,
}

impl SendStreamInner {
    fn new() -> Self {
        Self {
            data: VecDeque::new(),
            pending: IndexMap::new(),
            next_off: 0,
            final_size: None,
            apec: None,
        }
    }

    //emits data to be sent
    fn emit(&mut self, buf: &mut [u8], pn: u64) -> Result<(usize, bool), terror::Error> {
        if self.apec.is_some() {
            return Err(terror::Error::stream_error("stream has been reset"));
        }

        let mut written = 0;
        let mut remaining = buf.len();
        let mut fin = false;

        while remaining > 0 {
            //take first chunk
            let Some(mut chunk) = self.data.pop_front() else {
                break;
            };

            //check if there is anything in the current chunk to read
            if chunk.is_empty() {
                warn!("zero sized chunk occured");
                continue;
            }

            let to_write = std::cmp::min(remaining, chunk.len());

            //split chunk if neccessary
            if to_write < chunk.len() {
                let rest = chunk.split_at(to_write);
                self.data.push_front(rest);
            }

            buf[written..written + to_write].copy_from_slice(&chunk.data[..to_write]);

            fin = chunk.fin;

            //enter chunk into pending
            self.pending.insert(pn, chunk);

            written += to_write;
            remaining -= to_write;
        }

        Ok((written, fin))
    }

    //acks data that has been sent and drops it. if data inside chunk has 0 references it is
    //dropped
    fn ack(&mut self, pns: &[u64]) {
        for pn in pns {
            self.pending.swap_remove(pn);
        }
    }

    fn append(&mut self, data: &[u8], fin: bool) -> Result<(), terror::Error> {
        if self.final_size.is_some() {
            return Err(terror::Error::stream_error(
                "cannot append to finalized or reset stream",
            ));
        }

        if fin {
            self.final_size = Some(self.next_off as usize + data.len());
        }

        self.data.push_back(Chunk::new(data, self.next_off, fin));
        self.next_off += data.len() as u64;

        Ok(())
    }

    fn reset(&mut self, apec: u64) -> Result<(), terror::Error> {
        if self.apec.is_some() {
            return Err(terror::Error::stream_error("cannot reset stream twice"));
        }

        self.apec = Some(apec);
        self.final_size = Some(self.next_off as usize - 1);

        self.data.clear();
        self.pending.clear();

        Ok(())
    }
}

struct RecvStreamInner {
    //data chunks ordered by their offset
    data: IndexMap<u64, Chunk>,

    //keeps track of gaps in received data. must be sorted at all times
    gaps: Vec<Range<u64>>,

    //highest offset received
    max_off: u64,

    //highest chunk offset into [`data`] that has been read
    max_read: u64,

    //received stream frame with offset 0
    start_recv: bool,

    //final size in case of reset
    final_size: Option<u64>,

    //application error code received via reset
    apec: Option<u64>,
}

impl RecvStreamInner {
    fn new() -> Self {
        Self {
            data: IndexMap::new(),
            gaps: Vec::new(),
            max_off: 0,
            max_read: 0,
            start_recv: false,
            final_size: None,
            apec: None,
        }
    }

    fn with_data(data: &[u8], off: u64, fin: bool) -> Self {
        let chunk = Chunk::new(data, off, fin);
        let mut gaps = Vec::new();
        let mut start_recv = true;
        let mut final_size = None;

        //if first received frame is actually second, insert first gap
        if off > 0 {
            gaps.push(0..off);
            start_recv = false;
        }

        let mut map = IndexMap::new();
        map.insert(off, chunk);

        if fin {
            final_size = Some(data.len() as u64);
        }

        Self {
            data: map,
            gaps,
            max_off: off,
            max_read: 0,
            start_recv,
            final_size,
            apec: None,
        }
    }

    //processes a single stream frame on the receiving end. should a gap emerge, incoming frames
    //which have not been received already are matched to those gaps via their offset. Per RFC 9000 sec.
    //2.2: The data at a given offset MUST NOT change if it is sent multiple times; an endpoint MAY
    //  treat receipt of different data at the same offset within a stream as a connection error of
    //  type PROTOCOL_VIOLATION.
    //Therefore if a frame cannot be matched to a gap and no already received offset with matching
    //length exists, a Quic Transport Error is thrown.
    fn process(
        &mut self,
        offset: u64,
        length: u64,
        fin: bool,
        data: &[u8],
    ) -> Result<(), terror::Error> {
        //check if offset and length match any already received chunks
        if let Some(chunk) = self.data.get(&offset) {
            if chunk.len == length as usize {
                return Ok(());
            }
        }

        //if the stream has been reset or an offset is higher than the final
        if self.apec.is_some() {
            return Err(terror::Error::stream_error(
                "cannot process frame: stream reset",
            ));
        }

        //if chunk with offset zero is received, we can emit
        if offset == 0 {
            self.start_recv = true;
        }

        if let Some(fsize) = self.final_size {
            if offset > fsize {
                return Err(terror::Error::quic_transport_error(
                    "received offset higher than final size",
                    terror::QuicTransportError::FinalSizeError,
                ));
            }
        }

        //check if offset and length match to any known gaps and insert chunk
        if let Some(i) = self.match_offset_to_gap(offset) {
            let gap = self.gaps.remove(i);

            if offset > gap.end || (offset + length) > gap.end {
                return Err(terror::Error::quic_transport_error(
                    "malformed stream frame",
                    terror::QuicTransportError::ProtocolViolation,
                ));
            }

            let lower = gap.start..offset;
            let upper = offset + length..gap.end;

            if !lower.is_empty() {
                //insert lower gap as new range
                self.insert_gap(lower);
            }

            if !upper.is_empty() {
                //inser upper gap
                self.insert_gap(upper);
            }
        } else {
            //detect gaps in offset if offset is greater than next offset
            if let Some((last_off, last_chunk)) = self.data.last() {
                let succinct_offset = *last_off + last_chunk.len() as u64;
                if succinct_offset < offset {
                    self.insert_gap(succinct_offset..offset);
                }
            }
        }

        //insert chunk into sorted list
        self.data
            .insert_sorted(offset, Chunk::new(data, offset, fin));

        self.max_off = std::cmp::max(self.max_off, offset);

        if fin {
            self.final_size = Some(offset + length);
        }

        Ok(())
    }

    fn reset(&mut self, apec: u64, final_size: u64) -> Result<(), terror::Error> {
        if let Some(fsize) = self.final_size {
            if final_size != fsize {
                return Err(terror::Error::quic_transport_error(
                    format!(
                        "final size {} is not equal to already known final size {}",
                        final_size, fsize
                    ),
                    terror::QuicTransportError::FinalSizeError,
                ));
            }
        }

        if final_size < (self.max_off + self.data.get(&self.max_off).unwrap().len as u64) {
            return Err(terror::Error::quic_transport_error(
                "final size is smaller than already received stream length",
                terror::QuicTransportError::FinalSizeError,
            ));
        }

        self.final_size = Some(final_size);
        self.apec = Some(apec);

        //clear data
        self.data.clear();

        Ok(())
    }

    fn insert_gap(&mut self, gap: Range<u64>) {
        match self
            .gaps
            .binary_search_by(|probe| probe.start.cmp(&gap.start))
        {
            Ok(_) => {
                warn!("tried inserting gap in recv stream which already existed",);
            }
            Err(pos) => self.gaps.insert(pos, gap),
        }
    }

    fn match_offset_to_gap(&self, key: u64) -> Option<usize> {
        // Find the index of the first item where `range.start <= key`.
        let index = match self.gaps.binary_search_by_key(&key, |range| range.start) {
            Ok(index) => Some(index),

            // If the requested key is smaller than the smallest range in the slice,
            // we would be computing `0 - 1`, which would underflow an `usize`.
            // We use `checked_sub` to get `None` instead.
            Err(index) => index.checked_sub(1),
        };

        if let Some(index) = index {
            let range = &self.gaps[index];
            if key < range.end {
                return Some(index);
            }
        }

        None
    }

    fn consume(&mut self, buf: &mut [u8]) -> Result<usize, terror::Error> {
        if !self.start_recv {
            return Ok(0);
        }

        if let Some(apec) = self.apec {
            return Err(terror::Error::stream_error(format!(
                "stream has been reset with error code {}",
                apec
            )));
        }

        let mut written = 0;
        let mut remaining = buf.len();
        let mut max_read = self.max_read;

        while remaining > 0 {
            let chunk = self.data.get_mut(&max_read).unwrap();

            //check if there is anything in the current chunk to read
            if chunk.is_empty() {
                //check if next entry is readable
                let next_off = chunk.off + chunk.len as u64;

                if self.data.get(&next_off).is_some() {
                    max_read = next_off;
                    continue;
                } else {
                    break;
                }
            }

            let to_write = std::cmp::min(remaining, chunk.len());

            buf[written..written + to_write].copy_from_slice(&chunk.data);

            chunk.consume(to_write);

            written += to_write;
            remaining -= to_write;

            //check if all data has been consumed
            if chunk.is_empty() && chunk.fin {
                return Ok(written);
            }
        }

        self.max_read = max_read;

        Ok(written)
    }
}

//single chunk of data
struct Chunk {
    // Read only data
    data: Arc<Vec<u8>>,

    //start in data, used to be able to split data without copying buffer
    start: usize,

    // offset of chunk within stream
    off: u64,

    // relative position in chunk while consuming
    pos: usize,

    //chunk data length
    len: usize,

    //if this chunk is the last one for the stream
    fin: bool,
}

impl Chunk {
    fn new(data: &[u8], off: u64, fin: bool) -> Self {
        Self {
            data: Arc::new(data.to_vec()),
            start: 0,
            off,
            pos: 0,
            len: data.len(),
            fin,
        }
    }

    pub fn off(&self) -> u64 {
        (self.off - self.start as u64) + self.pos as u64
    }

    pub fn max_off(&self) -> u64 {
        self.off() + self.len() as u64
    }

    pub fn len(&self) -> usize {
        self.len - (self.pos - self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn consume(&mut self, len: usize) {
        self.pos += len;
    }

    pub fn split_at(&mut self, at: usize) -> Chunk {
        if self.len <= at {
            panic!("cannot split buffer at offset larger than its length");
        }

        let buf = Chunk {
            data: self.data.clone(),
            start: self.start + at,
            off: self.off + at as u64,
            pos: std::cmp::max(self.pos, self.start + at),
            len: self.len - at,
            fin: self.fin,
        };

        self.pos = std::cmp::min(self.pos, self.start + at);
        self.len = at;
        self.fin = false;

        buf
    }
}

impl std::ops::Deref for Chunk {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data[self.pos..self.start + self.len]
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_manager_create_as_server() {
        let mut sm = StreamManager::new(rustls::Side::Server as u8);

        let bidi1 = sm.initiate(true).unwrap();
        let bidi2 = sm.initiate(true).unwrap();

        let uni1 = sm.initiate(false).unwrap();
        let uni2 = sm.initiate(false).unwrap();

        assert_eq!(bidi1, 0x01);
        assert_eq!(bidi2, 0x05);
        assert_eq!(uni1, 0x03);
        assert_eq!(uni2, 0x07);
    }

    #[test]
    fn stream_manager_create_as_client() {
        let mut sm = StreamManager::new(rustls::Side::Client as u8);

        let bidi1 = sm.initiate(true).unwrap();
        let bidi2 = sm.initiate(true).unwrap();

        let uni1 = sm.initiate(false).unwrap();
        let uni2 = sm.initiate(false).unwrap();

        assert_eq!(bidi1, 0x00);
        assert_eq!(bidi2, 0x04);
        assert_eq!(uni1, 0x02);
        assert_eq!(uni2, 0x06);
    }

    #[test]
    fn stream_manager_incoming_as_server() {
        let mut sm = StreamManager::new(rustls::Side::Server as u8);

        let bidi1 = 0x00;
        let bidi2 = 0x04;
        let bidi3 = 0x08;

        let uni1 = 0x02;

        sm.incoming(bidi3, 0, 8, true, &[1u8; 8]).unwrap();

        assert_eq!(sm.counts[0], 3);
        assert!(sm.inbound.get(&bidi3).is_some());
        assert!(sm.outbound.get(&bidi3).is_some());

        sm.incoming(bidi2, 0, 8, true, &[1u8; 8]).unwrap();

        assert!(sm.inbound.get(&bidi2).is_some());
        assert!(sm.outbound.get(&bidi2).is_some());

        sm.incoming(bidi1, 0, 8, true, &[1u8; 8]).unwrap();

        assert!(sm.inbound.get(&bidi1).is_some());
        assert!(sm.outbound.get(&bidi1).is_some());

        sm.incoming(uni1, 0, 8, true, &[1u8; 8]).unwrap();

        assert_eq!(sm.counts[2], 1);
        assert!(sm.inbound.get(&uni1).is_some());
        assert!(sm.outbound.get(&uni1).is_none());
    }

    #[test]
    fn stream_manager_wrong_id_type_as_server() {
        let mut sm = StreamManager::new(rustls::Side::Server as u8);

        // server init bidi recv as server should fail
        let bidi = 0x05;

        assert!(sm.incoming(bidi, 0, 8, true, &[1u8; 8]).is_err());
    }

    #[test]
    fn recv_stream_creation() {
        let data = vec![1u8; 8];

        let recv_stream = RecvStreamInner::with_data(&data, 0, true);

        assert_eq!(recv_stream.max_off, 0);
        assert_eq!(recv_stream.final_size.unwrap(), 8);
    }

    #[test]
    fn recv_stream_gap_detection() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];
        let frame3 = vec![3u8; 8];

        let mut recv_stream = RecvStreamInner::with_data(&frame1, 0, false);
        assert!(recv_stream.process(16, 8, true, &frame3).is_ok());

        assert_eq!(recv_stream.gaps[0], 8..16);
        assert_eq!(recv_stream.max_off, 16);
        assert_eq!(recv_stream.final_size.unwrap(), 24);

        assert!(recv_stream.process(8, 8, false, &frame2).is_ok());
    }

    #[test]
    fn recv_stream_triple_gap_detection() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];
        let frame3 = vec![3u8; 8];
        let frame4 = vec![4u8; 8];
        let frame5 = vec![5u8; 8];

        let mut recv_stream = RecvStreamInner::with_data(&frame1, 0, false);
        assert!(recv_stream.process(32, 8, true, &frame5).is_ok());

        assert_eq!(recv_stream.gaps[0], 8..32);
        assert_eq!(recv_stream.max_off, 32);
        assert_eq!(recv_stream.final_size.unwrap(), 40);

        assert!(recv_stream.process(16, 8, false, &frame3).is_ok());

        assert_eq!(recv_stream.gaps, [8..16, 24..32]);

        assert!(recv_stream.process(24, 8, false, &frame4).is_ok());
        assert!(recv_stream.process(8, 8, false, &frame2).is_ok());
    }

    #[test]
    fn malformed_stream_frame() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 9];
        let frame3 = vec![3u8; 8];

        let mut recv_stream = RecvStreamInner::with_data(&frame1, 0, false);
        assert!(recv_stream.process(16, 8, true, &frame3).is_ok());
        assert!(recv_stream.process(8, 9, false, &frame2).is_err());
    }

    #[test]
    fn stream_initiated_with_gap() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];
        let frame3 = vec![3u8; 8];

        let mut recv_stream = RecvStreamInner::with_data(&frame2, 8, false);
        assert!(recv_stream.process(0, 8, false, &frame1).is_ok());
        assert!(recv_stream.process(16, 8, true, &frame3).is_ok());
    }

    #[test]
    fn index_map_preserves_order_by_offset() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];
        let frame3 = vec![3u8; 8];

        let mut recv_stream = RecvStreamInner::with_data(&frame1, 0, false);
        assert!(recv_stream.process(16, 8, true, &frame3).is_ok());
        assert!(recv_stream.process(8, 8, false, &frame2).is_ok());

        assert_eq!(recv_stream.data[0].off, 0);
        assert_eq!(recv_stream.data[1].off, 8);
        assert_eq!(recv_stream.data[2].off, 16);
    }

    #[test]
    fn recv_stream_read() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];
        let frame3 = vec![3u8; 8];

        let mut recv_stream = RecvStreamInner::with_data(&frame1, 0, false);
        assert!(recv_stream.process(16, 8, true, &frame3).is_ok());
        assert!(recv_stream.process(8, 8, false, &frame2).is_ok());

        let output = [
            1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3,
        ];
        let mut result = [0u8; 24];

        let size = recv_stream.consume(&mut result).unwrap();

        assert_eq!(size, output.len());
        assert_eq!(output, result);
    }

    #[test]
    fn recv_stream_read_with_gap() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];
        let frame3 = vec![3u8; 8];

        let mut result = [0u8; 24];

        let mut recv_stream = RecvStreamInner::with_data(&frame1, 0, false);
        assert!(recv_stream.process(16, 8, true, &frame3).is_ok());

        assert_eq!(recv_stream.final_size.unwrap(), 24);

        let read = recv_stream.consume(&mut result).unwrap();

        assert_eq!(read, 8);

        assert!(recv_stream.process(8, 8, false, &frame2).is_ok());

        let read = recv_stream.consume(&mut result[read..]).unwrap();

        assert_eq!(read, 16);

        let output = [
            1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3,
        ];

        assert_eq!(output, result);
    }

    #[test]
    fn recv_stream_reset() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];

        let mut recv_stream = RecvStreamInner::with_data(&frame1, 0, false);
        assert!(recv_stream.process(8, 8, false, &frame2).is_ok());
        assert!(recv_stream.reset(0x00, 16).is_ok());
    }

    #[test]
    fn recv_stream_reset_invalid_final_size_too_large() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];

        let mut recv_stream = RecvStreamInner::with_data(&frame1, 0, false);
        assert!(recv_stream.process(8, 8, true, &frame2).is_ok());
        assert!(recv_stream.reset(0x00, 17).is_err());
    }

    #[test]
    fn recv_stream_reset_invalid_final_size_too_small() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];

        let mut recv_stream = RecvStreamInner::with_data(&frame1, 0, false);
        assert!(recv_stream.process(8, 8, false, &frame2).is_ok());
        assert!(recv_stream.reset(0x00, 15).is_err());
    }

    #[test]
    fn send_stream_emit() {
        let frame1 = vec![1u8; 8];
        let mut result = vec![0u8; 8];

        let mut send_stream = SendStreamInner::new();

        send_stream.append(&frame1, true).unwrap();

        let (size, fin) = send_stream.emit(&mut result, 0).unwrap();

        assert!(fin);
        assert_eq!(size, 8);

        assert!(send_stream.pending.get(&0).is_some());
    }

    #[test]
    fn send_stream_emit_split_chunk() {
        let frame1 = vec![1u8; 8];
        let mut result = [0u8; 8];

        let mut send_stream = SendStreamInner::new();

        send_stream.append(&frame1, true).unwrap();

        let (size, fin) = send_stream.emit(&mut result[..4], 0).unwrap();

        assert!(!fin);
        assert_eq!(size, 4);

        assert!(send_stream.pending.get(&0).is_some());
        assert!(send_stream.data.front().is_some());

        let (size, fin) = send_stream.emit(&mut result[4..], 1).unwrap();

        assert!(fin);
        assert_eq!(size, 4);

        assert!(send_stream.pending.get(&1).is_some());
        assert!(send_stream.data.front().is_none());
    }

    #[test]
    fn send_stream_ack() {
        let frame1 = vec![1u8; 8];
        let mut result = vec![0u8; 8];

        let mut send_stream = SendStreamInner::new();

        send_stream.append(&frame1, true).unwrap();

        let (size, fin) = send_stream.emit(&mut result, 0).unwrap();

        assert!(fin);
        assert_eq!(size, 8);

        send_stream.ack(&[0]);

        assert!(send_stream.pending.is_empty());
    }

    #[test]
    fn send_stream_reset() {
        let frame1 = vec![1u8; 8];
        let mut result = vec![0u8; 8];

        let mut send_stream = SendStreamInner::new();

        send_stream.append(&frame1, false).unwrap();

        send_stream.reset(0xf).unwrap();

        assert!(send_stream.pending.is_empty());

        //assert appending and emitting is disabled after reset
        assert!(send_stream.append(&frame1, true).is_err());
        assert!(send_stream.emit(&mut result, 0).is_err());
    }
}
