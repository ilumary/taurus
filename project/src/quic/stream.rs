use crate::terror;

use std::{collections::VecDeque, ops::Range, sync::Arc};

use indexmap::IndexMap;
use tracing::{error, warn};

const STREAM_TYPE: u64 = 0x3;
const CLIENT_INIT_BIDI: u64 = 0x00;
const SERVER_INIT_BIDI: u64 = 0x01;
const CLIENT_INIT_UNI: u64 = 0x02;
const SERVER_INIT_UNI: u64 = 0x03;

type StreamId = u64;

// stores and manages streams for connection
// TODO register callback on recv stream
// TODO initialize with limits
pub struct StreamManager {
    outbound: IndexMap<StreamId, SendStream>,
    inbound: IndexMap<StreamId, RecvStream>,
}

impl StreamManager {
    pub fn new() -> Self {
        Self {
            inbound: IndexMap::new(),
            outbound: IndexMap::new(),
        }
    }

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

        //new incoming stream, must be at least an RecvStream because its incoming
        let recv = RecvStream::new(stream_id, data, offset, fin);

        let send = if stream_id & STREAM_TYPE == CLIENT_INIT_BIDI
            || stream_id & STREAM_TYPE == SERVER_INIT_BIDI
        {
            Some(SendStream::new(stream_id))
        } else {
            None
        };

        if self.inbound.insert(stream_id, recv).is_none() {
            return Err(terror::Error::stream_error(format!(
                "failed to insert recv stream with stream id {}",
                stream_id
            )));
        }

        if let Some(s) = send {
            if self.outbound.insert(stream_id, s).is_none() {
                return Err(terror::Error::stream_error(format!(
                    "failed to insert send stream with stream id {}",
                    stream_id
                )));
            }
        }

        Ok(())
    }

    //TODO rework for bidi streams as well as uni streams
    pub fn process_reset(
        &mut self,
        stream_id: u64,
        apec: u64,
        final_size: u64,
    ) -> Result<(), terror::Error> {
        if let Some(rs) = self.inbound.get_mut(&stream_id) {
            rs.reset(apec, final_size)?;
            warn!(
                "stream {} has been reset with error code {}",
                stream_id, apec
            );
        } else {
            error!("received reset for stream that does not exist");
        }

        Ok(())
    }

    pub fn _initiate_unidirectional(
        &mut self,
        _data: Vec<u8>,
    ) -> Result<SendStream, terror::Error> {
        todo!("initiating streams is not yet implemented");
    }

    pub fn _initiate_bidirectional(
        &mut self,
        _data: Vec<u8>,
    ) -> Result<(SendStream, RecvStream), terror::Error> {
        todo!("initiating streams is not yet implemented");
    }
}

//TODO retransmits
pub struct SendStream {
    id: StreamId,

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

impl SendStream {
    fn new(id: StreamId) -> Self {
        Self {
            id,
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

pub struct RecvStream {
    id: StreamId,

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

impl RecvStream {
    fn new(id: StreamId, data: &[u8], off: u64, fin: bool) -> Self {
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
            id,
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
                    format!("malformed frame in stream {}", self.id),
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
                warn!(
                    "tried inserting gap in recv stream {} which already existed",
                    self.id
                );
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
    fn recv_stream_creation() {
        let data = vec![1u8; 8];

        let recv_stream = RecvStream::new(0, &data, 0, true);

        assert_eq!(recv_stream.max_off, 0);
        assert_eq!(recv_stream.final_size.unwrap(), 8);
    }

    #[test]
    fn recv_stream_gap_detection() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];
        let frame3 = vec![3u8; 8];

        let mut recv_stream = RecvStream::new(0, &frame1, 0, false);
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

        let mut recv_stream = RecvStream::new(0, &frame1, 0, false);
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

        let mut recv_stream = RecvStream::new(0, &frame1, 0, false);
        assert!(recv_stream.process(16, 8, true, &frame3).is_ok());
        assert!(recv_stream.process(8, 9, false, &frame2).is_err());
    }

    #[test]
    fn stream_initiated_with_gap() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];
        let frame3 = vec![3u8; 8];

        let mut recv_stream = RecvStream::new(0, &frame2, 8, false);
        assert!(recv_stream.process(0, 8, false, &frame1).is_ok());
        assert!(recv_stream.process(16, 8, true, &frame3).is_ok());
    }

    #[test]
    fn index_map_preserves_order_by_offset() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];
        let frame3 = vec![3u8; 8];

        let mut recv_stream = RecvStream::new(0, &frame1, 0, false);
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

        let mut recv_stream = RecvStream::new(0, &frame1, 0, false);
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

        let mut recv_stream = RecvStream::new(0, &frame1, 0, false);
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

        let mut recv_stream = RecvStream::new(0, &frame1, 0, false);
        assert!(recv_stream.process(8, 8, false, &frame2).is_ok());
        assert!(recv_stream.reset(0x00, 16).is_ok());
    }

    #[test]
    fn recv_stream_reset_invalid_final_size_too_large() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];

        let mut recv_stream = RecvStream::new(0, &frame1, 0, false);
        assert!(recv_stream.process(8, 8, true, &frame2).is_ok());
        assert!(recv_stream.reset(0x00, 17).is_err());
    }

    #[test]
    fn recv_stream_reset_invalid_final_size_too_small() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];

        let mut recv_stream = RecvStream::new(0, &frame1, 0, false);
        assert!(recv_stream.process(8, 8, false, &frame2).is_ok());
        assert!(recv_stream.reset(0x00, 15).is_err());
    }

    #[test]
    fn send_stream_emit() {
        let frame1 = vec![1u8; 8];
        let mut result = vec![0u8; 8];

        let mut send_stream = SendStream::new(0);

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

        let mut send_stream = SendStream::new(0);

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

        let mut send_stream = SendStream::new(0);

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

        let mut send_stream = SendStream::new(0);

        send_stream.append(&frame1, false).unwrap();

        send_stream.reset(0xf).unwrap();

        assert!(send_stream.pending.is_empty());

        //assert appending and emitting is disabled after reset
        assert!(send_stream.append(&frame1, true).is_err());
        assert!(send_stream.emit(&mut result, 0).is_err());
    }
}
