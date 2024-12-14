use crate::{terror, Connection};

use std::{
    collections::{BTreeSet, VecDeque},
    future,
    ops::Range,
    sync::Arc,
};

use indexmap::IndexMap;
use octets::varint_len;
use tracing::{debug, warn};

const STREAM_TYPE: u64 = 0x3;
const CLIENT_INIT_BIDI: u64 = 0x00;
const SERVER_INIT_BIDI: u64 = 0x01;
const CLIENT_INIT_UNI: u64 = 0x02;
const SERVER_INIT_UNI: u64 = 0x03;

type StreamId = u64;
type StreamPriority = u8;

// public struct for the RecvStream, maybe also add reference to actual stream object to save on
// search in indexmap
pub struct RecvStream {
    pub id: StreamId,
    inner: Connection,
}

impl RecvStream {
    pub fn new(id: StreamId, inner: Connection) -> Self {
        Self { id, inner }
    }

    // Reads data from a stream into the provided buffer. If successfull, returns number of bytes
    // read. Existing data in the buffer is overwritten. Returns [`None`] if the stream is finished
    // or has been reset.
    pub async fn read(&self, buf: &mut [u8]) -> Result<Option<usize>, terror::Error> {
        future::poll_fn(|cx| self.inner.api.poll_recv(cx, &self.id, buf)).await
    }
}

// public struct for the SendStream
pub struct SendStream {
    pub id: StreamId,
    inner: Connection,
}

impl SendStream {
    pub fn new(id: StreamId, inner: Connection) -> Self {
        Self { id, inner }
    }

    // Writes data to a send stream. Returns the number of bytes written. Due to flow control
    // limits it is not guaranteed that all data will be appended. Writing to a finished or reset
    // stream returns an error.
    pub async fn write(&self, buf: &[u8], fin: bool) -> Result<usize, terror::Error> {
        future::poll_fn(|cx| self.inner.api.poll_send(cx, &self.id, buf, fin)).await
    }
}

// stream waker for async lib, wakes stored task waker when invoked. allows tasks to wait until a
// new stream is ready or readable data arrived in a recv_stream. also used when certain stream
// limits are exceeded
#[derive(Clone)]
pub struct StreamWaker {
    wk: std::task::Waker,
}

impl StreamCallback for StreamWaker {
    type Callback = std::task::Waker;

    fn new(wk: std::task::Waker) -> Self {
        Self { wk }
    }

    fn invoke(self) {
        self.wk.wake()
    }
}

// stream callback trait. requires that the callback type can be cloned
pub trait StreamCallback {
    type Callback;

    fn new(wk: Self::Callback) -> Self;

    fn invoke(self);
}

// stores and manages streams for connection
// TODO initialize with limits
pub struct StreamManager<C: StreamCallback> {
    // all streams, sorted by inbound and outbound
    outbound: IndexMap<StreamId, SendStreamInner>,
    inbound: IndexMap<StreamId, RecvStreamInner<C>>,

    // [client init bidi, server init bidi, client init uni, server init uni]
    counts: [u64; 4],

    // holds the lowest unconsumed stream id
    ready: [Option<u64>; 4],

    // if no ready stream was found, a callback is saved. Only one callback per stream type can be
    // saved. The callback is consumed when invoked
    callbacks: [Option<C>; 4],

    // keeps track of outbound streams which have data to write. Key for the tree is a tuple
    // of StreamPriority & StreamId. Tuples implement ord from left to right, so first stream
    // id has highest priority (1) and multiple streams with the same priority are ordered by
    // acending id
    outbound_ready: BTreeSet<(StreamPriority, StreamId)>,

    // keeps track of pending acks by packet number
    // unique set (pn, stream_id)
    ack_pending: IndexMap<u64, Vec<StreamId>>,

    // used as least significant bit in stream ids. distinguishes between client (0x00) and server
    // (0x01)
    local: u8,
}

impl<C: StreamCallback> StreamManager<C> {
    pub fn new(local: u8) -> Self {
        assert!(local == 0x00 || local == 0x01, "local must be 0x00 or 0x01");

        Self {
            inbound: IndexMap::new(),
            outbound: IndexMap::new(),
            outbound_ready: BTreeSet::new(),
            ack_pending: IndexMap::new(),
            counts: [0, 0, 0, 0],
            ready: [None; 4],
            callbacks: [None, None, None, None],
            local,
        }
    }

    // polls for specific stream type. if no ready stream was found, save callback
    pub fn poll_ready(&mut self, stream_t: u64, cb: C::Callback) -> Option<StreamId> {
        let stream_t: usize = stream_t as usize;
        if let Some(id) = self.ready[stream_t] {
            //if ready id is availibe, check if higher id exists
            let sequence = id >> 2;
            if sequence < self.counts[stream_t] - 1 {
                self.ready[stream_t] = Some(id + 4);
            } else {
                self.ready[stream_t] = None;
            }

            return Some(id);
        }

        // no ready stream was found, save callback
        self.callbacks[stream_t] = Some(C::new(cb));

        None
    }

    // creates a new stream with a given stream id
    fn create(
        &mut self,
        stream_id: StreamId,
        priority: Option<StreamPriority>,
        local: bool,
    ) -> Result<(), terror::Error> {
        if self.inbound.contains_key(&stream_id) || self.outbound.contains_key(&stream_id) {
            return Err(terror::Error::stream_error("stream does already exist"));
        }

        let stream_t = stream_id & STREAM_TYPE;
        let sequence = stream_id >> 2;

        if sequence >= self.counts[stream_t as usize] {
            self.counts[stream_t as usize] = sequence + 1;
        }

        if stream_t == CLIENT_INIT_BIDI || stream_t == SERVER_INIT_BIDI {
            self.inbound
                .insert(stream_id, RecvStreamInner::new(priority));
            self.outbound
                .insert(stream_id, SendStreamInner::new(priority));
        } else if (stream_t == CLIENT_INIT_UNI || stream_t == SERVER_INIT_UNI) && local {
            // if stream is unidirectional and created locally it is always outbound
            self.outbound
                .insert(stream_id, SendStreamInner::new(priority));
        } else if (stream_t == CLIENT_INIT_UNI || stream_t == SERVER_INIT_UNI) && !local {
            // if it is not locally created it must be inbound
            self.inbound
                .insert(stream_id, RecvStreamInner::new(priority));
        }

        debug!("created stream {{id: {stream_id}}}");

        Ok(())
    }

    // issues a new stream id and creates a new stream
    // TODO check local stream limits
    pub fn initiate(
        &mut self,
        bidi: bool,
        priority: Option<StreamPriority>,
    ) -> Result<StreamId, terror::Error> {
        // issue new stream id, start with locality
        let mut id = self.local as u64;

        // a bit of parsing to add bidirectionality to id
        id |= (!bidi as u64) << 1;

        // now add sequence number aka the inner id
        id |= self.counts[id as usize] << 2;

        self.create(id, priority, true)?;

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
        self.create(stream_id, None, false)?;

        // unwrap is safe because stream was created
        let recv_s = self.inbound.get_mut(&stream_id).unwrap();
        recv_s.process(offset, length, fin, data)?;

        // save stream as ready
        let stream_t = stream_id & STREAM_TYPE;
        if self.ready[stream_t as usize].is_none() {
            self.ready[stream_t as usize] = Some(stream_id);
        }

        // invoke callback if present
        if let Some(c) = self.callbacks[stream_t as usize].take() {
            c.invoke();
        }

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
    ) -> Result<usize, terror::Error> {
        if let Some(ss) = self.outbound.get_mut(&stream_id) {
            let len = ss.append(data, fin)?;
            self.outbound_ready.insert((ss.prio, stream_id));
            return Ok(len);
        }

        Err(terror::Error::invalid_stream(format!(
            "invalid stream id {stream_id}",
        )))
    }

    // consumes data from an existing inbound stream
    pub fn consume(
        &mut self,
        stream_id: &StreamId,
        buf: &mut [u8],
        wk: C::Callback,
    ) -> Result<Option<usize>, terror::Error> {
        let stream = match self.inbound.get_mut(stream_id) {
            Some(s) => s,
            None => return Err(terror::Error::invalid_stream("invalid stream id")),
        };

        let read = stream.consume(buf);

        if let Some(0) = read {
            stream.callback = Some(C::new(wk));
        }

        Ok(read)
    }

    //modifies a streams priority, a possible entry into outbound ready is updated
    pub fn set_priority(
        &mut self,
        stream_id: StreamId,
        priority: StreamPriority,
    ) -> Result<(), terror::Error> {
        let mut old_prio = StreamPriority::MAX;

        if let Some(rs) = self.inbound.get_mut(&stream_id) {
            old_prio = rs.prio;
            rs.prio = priority;
        }

        if let Some(ss) = self.outbound.get_mut(&stream_id) {
            old_prio = ss.prio;
            ss.prio = priority;
        }

        self.outbound_ready.remove(&(old_prio, stream_id));
        self.outbound_ready.insert((priority, stream_id));

        Ok(())
    }

    //fills the frame with stream frames
    pub fn emit_fill(&mut self, buf: &mut [u8], pn: u64) -> Result<usize, terror::Error> {
        let mut written = 0;
        let mut remaining = buf.len();

        while remaining > 0 {
            let b = self.emit_single(&mut buf[written..], pn)?;

            if b == 0 {
                break;
            }

            remaining -= b;
            written += b;
        }

        Ok(written)
    }

    //emits a single stream frame onto the buffer from the stream with the highest priority i.e.
    //the lowest number. if two streams have the same priority, the lower stream id is prioritised
    pub fn emit_single(&mut self, buf: &mut [u8], pn: u64) -> Result<usize, terror::Error> {
        let mut octets = octets::OctetsMut::with_slice(buf);

        //take first ready stream with outbound data
        let Some((p, ss_id)) = self.outbound_ready.first() else {
            return Ok(0);
        };

        let Some(ss) = self.outbound.get_mut(ss_id) else {
            return Err(terror::Error::stream_error(format!(
                "outbound stream (id: {}) with ready data does not exist",
                ss_id
            )));
        };

        // peek current offset and relative length of stream that is writeable
        let (stream_off, rel_length) = ss.peek();

        // calculate stram frame overhead
        let mut overhead = 1 + varint_len(*ss_id);

        if stream_off > 0 {
            overhead += varint_len(stream_off as u64);
        }

        //if there not enough space for frame overhead plus at least one byte of data, return
        if overhead + 1 > octets.len() {
            debug!("buffer too small for stream frame");
        }

        let mut stream_header: u8 = 0x08;
        let (mut stream_header_raw, mut rest) = octets.split_at(1)?;

        rest.put_varint(*ss_id)?;

        if stream_off > 0 {
            stream_header |= 0x04; //OFF
            rest.put_varint(stream_off as u64)?;
        }

        if rest.cap() > rel_length {
            //length field has to be included
            stream_header |= 0x02;
            overhead += rest.put_varint(rel_length as u64)?.len();
        }

        let (data_len, fin) = ss.emit(rest.as_mut(), pn)?;

        if fin {
            stream_header |= 0x01;
        }

        //add stream id to pending ack
        if let Some(v) = self.ack_pending.get_mut(&pn) {
            v.push(*ss_id);
        } else {
            self.ack_pending.insert(pn, vec![*ss_id]);
        }

        //write stream header last
        stream_header_raw.put_u8(stream_header)?;

        debug!("STREAM frame: id {ss_id} off {stream_off} len {data_len} fin {fin}");

        if !ss.readable() {
            self.outbound_ready.remove(&(*p, *ss_id));
        }

        Ok(data_len + overhead)
    }

    //acks a set of ranges of packet numbers. Each packet number may ack frames for multiple
    //streams.
    pub fn ack(&mut self, pns: Vec<u64>) -> Result<(), terror::Error> {
        for pn in pns {
            if let Some(ids) = self.ack_pending.get_mut(&pn) {
                for id in ids {
                    if let Some(ss) = self.outbound.get_mut(id) {
                        ss.pending.swap_remove(&pn);
                    }
                }
            }
        }
        Ok(())
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

    //holds final size if known
    final_size: Option<usize>,

    //application error code in case stream is reset
    apec: Option<u64>,

    //stream priority, lower is better
    prio: StreamPriority,

    //current length of all stream data
    length: usize,

    //current offset of internal data being sent
    off: usize,
    //Callback, triggered when either a) new data can be appended b) the stream is reset
}

impl SendStreamInner {
    fn new(priority: Option<StreamPriority>) -> Self {
        Self {
            data: VecDeque::new(),
            pending: IndexMap::new(),
            final_size: None,
            apec: None,
            prio: priority.unwrap_or(u8::MAX),
            length: 0,
            off: 0,
        }
    }

    fn readable(&self) -> bool {
        (self.length - self.off) > 0
    }

    //peeks sendable data to be able to build stream frame. returns (off, rel_len)
    fn peek(&self) -> (usize, usize) {
        (self.off, self.length - self.off)
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

        self.off += written;

        Ok((written, fin))
    }

    // TODO flow control limits
    fn append(&mut self, data: &[u8], fin: bool) -> Result<usize, terror::Error> {
        if self.final_size.is_some() {
            return Err(terror::Error::stream_error(
                "cannot append to finalized or reset stream",
            ));
        }

        if fin {
            self.final_size = Some(self.length + data.len());
        }

        self.data
            .push_back(Chunk::new(data, self.length as u64, fin));
        self.length += data.len();

        Ok(data.len())
    }

    fn reset(&mut self, apec: u64) -> Result<(), terror::Error> {
        if self.apec.is_some() {
            return Err(terror::Error::stream_error("cannot reset stream twice"));
        }

        self.apec = Some(apec);
        self.final_size = Some(self.length);
        self.off = self.length;

        self.data.clear();
        self.pending.clear();

        Ok(())
    }
}

struct RecvStreamInner<C: StreamCallback> {
    //data chunks ordered by their offset
    data: IndexMap<u64, Chunk>,

    //keeps track of gaps in received data. must be sorted at all times
    gaps: Vec<Range<u64>>,

    //highest offset received
    max_off: u64,

    //highest chunk offset into [`data`] that has been read
    max_read: u64,

    //number of bytes that have been read from the stream
    bytes_read: usize,

    //received stream frame with offset 0
    start_recv: bool,

    //final size in case of reset
    final_size: Option<u64>,

    //application error code received via reset
    apec: Option<u64>,

    //stream priority
    prio: StreamPriority,

    //Callback, triggered when either a) new incoming data is available b) the stream is reset
    callback: Option<C>,
}

impl<C: StreamCallback> RecvStreamInner<C> {
    fn new(priority: Option<StreamPriority>) -> Self {
        Self {
            data: IndexMap::new(),
            gaps: Vec::new(),
            max_off: 0,
            max_read: 0,
            bytes_read: 0,
            start_recv: false,
            final_size: None,
            apec: None,
            prio: priority.unwrap_or(u8::MAX),
            callback: None,
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

        // invoke callback to notify that new data is available
        if let Some(c) = self.callback.take() {
            c.invoke();
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

        // clear data
        self.data.clear();

        // invoke callback in case stream is reset
        if let Some(c) = self.callback.take() {
            c.invoke();
        }

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

    fn consume(&mut self, buf: &mut [u8]) -> Option<usize> {
        if !self.start_recv {
            return Some(0);
        }

        if self.apec.is_some() {
            return None;
        }

        if let Some(fs) = self.final_size {
            if fs == self.bytes_read as u64 {
                return None;
            }
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

            buf[written..written + to_write].copy_from_slice(&chunk.data[..to_write]);

            chunk.consume(to_write);

            written += to_write;
            remaining -= to_write;

            //check if all data has been consumed
            if chunk.is_empty() && chunk.fin {
                return Some(written);
            }
        }

        self.max_read = max_read;
        self.bytes_read += written;

        Some(written)
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

    impl<C: StreamCallback> RecvStreamInner<C> {
        // test only implementation to allow creation with data
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
                bytes_read: 0,
                start_recv,
                final_size,
                apec: None,
                prio: u8::MAX,
                callback: None,
            }
        }
    }

    // test adapter for stream waker
    #[derive(Clone)]
    pub struct TestStreamWaker {
        _waked: bool,
    }

    impl StreamCallback for TestStreamWaker {
        type Callback = bool;

        fn new(waked: bool) -> Self {
            Self { _waked: waked }
        }

        fn invoke(self) {}
    }

    #[test]
    fn stream_manager_create_as_server() {
        let mut sm = StreamManager::<TestStreamWaker>::new(rustls::Side::Server as u8);

        let bidi1 = sm.initiate(true, None).unwrap();
        let bidi2 = sm.initiate(true, None).unwrap();

        let uni1 = sm.initiate(false, None).unwrap();
        let uni2 = sm.initiate(false, None).unwrap();

        assert_eq!(bidi1, 0x01);
        assert_eq!(bidi2, 0x05);
        assert_eq!(uni1, 0x03);
        assert_eq!(uni2, 0x07);
    }

    #[test]
    fn stream_manager_create_as_client() {
        let mut sm = StreamManager::<TestStreamWaker>::new(rustls::Side::Client as u8);

        let bidi1 = sm.initiate(true, None).unwrap();
        let bidi2 = sm.initiate(true, None).unwrap();

        let uni1 = sm.initiate(false, None).unwrap();
        let uni2 = sm.initiate(false, None).unwrap();

        assert_eq!(bidi1, 0x00);
        assert_eq!(bidi2, 0x04);
        assert_eq!(uni1, 0x02);
        assert_eq!(uni2, 0x06);
    }

    #[test]
    fn stream_manager_incoming_as_server() {
        let mut sm = StreamManager::<TestStreamWaker>::new(rustls::Side::Server as u8);

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
        let mut sm = StreamManager::<TestStreamWaker>::new(rustls::Side::Server as u8);

        // server init bidi recv as server should fail
        let bidi = 0x05;

        assert!(sm.incoming(bidi, 0, 8, true, &[1u8; 8]).is_err());
    }

    #[test]
    fn stream_manager_emit_single() {
        let mut sm = StreamManager::<TestStreamWaker>::new(rustls::Side::Server as u8);
        let mut result = [0u8; 10];

        let send_stream = sm.initiate(false, None).unwrap();
        sm.append(send_stream, &[4u8; 8], true).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let written = sm.emit_single(&mut result, 0x00).unwrap();

        assert_eq!(result[0], 0x09);
        assert_eq!(result[1] as u64, send_stream);
        assert_eq!(result[2], 4);
        assert_eq!(result[8], 4);
        assert_eq!(written, 10);
        assert!(sm.outbound_ready.is_empty());
    }

    //TODO test that a stream id higher than the current sequence implicitly creates all streams
    //inbetween

    #[test]
    fn stream_manager_poll_ready() {
        let mut sm = StreamManager::<TestStreamWaker>::new(rustls::Side::Server as u8);

        let bidi1 = 0x00;
        sm.incoming(bidi1, 0, 8, true, &[1u8; 8]).unwrap();

        assert_eq!(sm.ready[0x00], Some(0x00));

        let id = sm.poll_ready(0x00, false).unwrap();

        assert_eq!(id, 0x00);
        assert!(sm.ready[0x00].is_none());
    }

    #[test]
    fn stream_manager_poll_ready_multiple() {
        let mut sm = StreamManager::<TestStreamWaker>::new(rustls::Side::Server as u8);

        let bidi1 = 0x00;
        sm.incoming(bidi1, 0, 8, true, &[1u8; 8]).unwrap();

        assert_eq!(sm.ready[0x00], Some(0x00));

        let bidi2 = 0x04;
        sm.incoming(bidi2, 0, 8, true, &[2u8; 8]).unwrap();

        assert_eq!(sm.ready[0x00], Some(0x00));

        let id = sm.poll_ready(0x00, false).unwrap();

        assert_eq!(id, 0x00);
        assert_eq!(sm.ready[0x00], Some(0x04));
    }

    #[test]
    fn stream_manager_incoming_invokes_callback() {
        let mut sm = StreamManager::<TestStreamWaker>::new(rustls::Side::Server as u8);

        let id = sm.poll_ready(0x00, false);

        assert!(id.is_none());
        assert!(sm.callbacks[0x00].is_some());

        let bidi1 = 0x00;
        sm.incoming(bidi1, 0, 8, true, &[1u8; 8]).unwrap();

        assert_eq!(sm.ready[0x00], Some(0x00));
        assert!(sm.callbacks[0x00].is_none());
    }

    #[test]
    fn stream_manager_emit_single_with_len() {
        let mut sm = StreamManager::<TestStreamWaker>::new(rustls::Side::Server as u8);
        let mut result = [0u8; 16];

        let send_stream = sm.initiate(false, None).unwrap();
        sm.append(send_stream, &[4u8; 8], true).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let written = sm.emit_single(&mut result, 0x00).unwrap();

        assert_eq!(result[0], 0x0b);
        assert_eq!(result[1] as u64, send_stream);
        assert_eq!(result[2], 8); //LEN
        assert_eq!(result[3], 4); //DATA BEGIN
        assert_eq!(result[9], 4); //DATA END
        assert_eq!(written, 11);
        assert!(sm.outbound_ready.is_empty());
    }

    #[test]
    fn stream_manager_emit_single_multiple() {
        let mut sm = StreamManager::<TestStreamWaker>::new(rustls::Side::Server as u8);
        let mut result = [0u8; 32];

        let send_stream = sm.initiate(false, None).unwrap();
        sm.append(send_stream, &[4u8; 10], false).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let written = sm.emit_single(&mut result[..8], 0x00).unwrap();

        assert_eq!(result[0], 0x08);
        assert_eq!(result[1] as u64, send_stream);
        assert_eq!(result[2], 4); //DATA BEGIN
        assert_eq!(result[7], 4); //DATA END
        assert_eq!(written, 8);
        assert!(!sm.outbound_ready.is_empty());

        sm.append(send_stream, &[5u8; 10], true).unwrap();

        let written2 = sm.emit_single(&mut result[8..], 0x00).unwrap();

        assert_eq!(result[8], 0x0f);
        assert_eq!(result[9] as u64, send_stream);
        assert_eq!(result[10], 6); //OFF
        assert_eq!(result[11], 14); //LEN
        assert_eq!(result[12], 4); //DATA BEGIN
        assert_eq!(result[25], 5); //DATA END
        assert_eq!(written2, 4 + 14); //HEADER + DATA LEN
        assert!(sm.outbound_ready.is_empty());
    }

    #[test]
    fn stream_manager_emit_with_prio() {
        let mut sm = StreamManager::<TestStreamWaker>::new(rustls::Side::Server as u8);
        let mut result = [0u8; 32];

        let send_stream = sm.initiate(false, None).unwrap();
        sm.append(send_stream, &[4u8; 32], false).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let send_stream2 = sm.initiate(false, Some(100)).unwrap();
        sm.append(send_stream2, &[5u8; 16], true).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (100, send_stream2));

        let written = sm.emit_single(&mut result, 0x00).unwrap();

        assert_eq!(result[0], 0x0b);
        assert_eq!(result[1] as u64, send_stream2);
        assert_eq!(result[2], 16); //LEN
        assert_eq!(result[3], 5); //DATA BEGIN
        assert_eq!(result[18], 5); //DATA END
        assert_eq!(written, 19);

        let written2 = sm.emit_single(&mut result[written..], 0x00).unwrap();

        assert_eq!(result[19], 0x08);
        assert_eq!(result[20] as u64, send_stream);
        assert_eq!(result[21], 4); //DATA BEGIN
        assert_eq!(result[31], 4); //DATA END
        assert_eq!(written2, 13);
        assert!(!sm.outbound_ready.is_empty());
    }

    #[test]
    fn stream_manager_emit_and_modifiy_stream_prio() {
        let mut sm = StreamManager::<TestStreamWaker>::new(rustls::Side::Server as u8);
        let mut result = [0u8; 32];

        let send_stream = sm.initiate(false, None).unwrap();
        sm.append(send_stream, &[4u8; 32], false).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let send_stream2 = sm.initiate(false, Some(100)).unwrap();
        sm.append(send_stream2, &[5u8; 16], true).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (100, send_stream2));

        let send_stream3 = sm.initiate(false, Some(10)).unwrap();
        sm.append(send_stream3, &[6u8; 16], true).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (10, send_stream3));

        let written = sm.emit_single(&mut result, 0x00).unwrap();

        assert_eq!(result[0], 0x0b);
        assert_eq!(result[1] as u64, send_stream3);
        assert_eq!(result[2], 16); //LEN
        assert_eq!(result[3], 6); //DATA BEGIN
        assert_eq!(result[18], 6); //DATA END
        assert_eq!(written, 19);

        sm.set_priority(send_stream, 5).unwrap();
        let written2 = sm.emit_single(&mut result[written..], 0x00).unwrap();

        assert_eq!(result[19], 0x08);
        assert_eq!(result[20] as u64, send_stream);
        assert_eq!(result[21], 4); //DATA BEGIN
        assert_eq!(result[31], 4); //DATA END
        assert_eq!(written2, 13);
        assert!(!sm.outbound_ready.is_empty());
    }

    #[test]
    fn stream_manager_emit_fill() {
        let mut sm = StreamManager::<TestStreamWaker>::new(rustls::Side::Server as u8);
        let mut result = [0u8; 48];

        let send_stream = sm.initiate(false, None).unwrap();
        sm.append(send_stream, &[4u8; 16], false).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let send_stream2 = sm.initiate(false, None).unwrap();
        sm.append(send_stream2, &[5u8; 16], true).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let send_stream3 = sm.initiate(false, None).unwrap();
        sm.append(send_stream3, &[6u8; 32], true).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let written = sm.emit_fill(&mut result, 0x00).unwrap();

        //stream 1
        assert_eq!(result[0], 0x0a);
        assert_eq!(result[1] as u64, send_stream);
        assert_eq!(result[2], 16); //LEN
        assert_eq!(result[3], 4); //DATA BEGIN
        assert_eq!(result[18], 4); //DATA END

        //stream 2
        assert_eq!(result[19], 0x0b);
        assert_eq!(result[20] as u64, send_stream2);
        assert_eq!(result[21], 16); //LEN
        assert_eq!(result[22], 5); //DATA BEGIN
        assert_eq!(result[37], 5); //DATA END

        //stream 3
        assert_eq!(result[38], 0x08);
        assert_eq!(result[39] as u64, send_stream3);
        assert_eq!(result[40], 6); //DATA BEGIN
        assert_eq!(result[47], 6); //DATA END

        assert_eq!(written, 48);
        assert!(!sm.outbound_ready.is_empty());
    }

    #[test]
    fn recv_stream_creation() {
        let data = vec![1u8; 8];

        let recv_stream = RecvStreamInner::<TestStreamWaker>::with_data(&data, 0, true);

        assert_eq!(recv_stream.max_off, 0);
        assert_eq!(recv_stream.final_size.unwrap(), 8);
    }

    #[test]
    fn recv_stream_gap_detection() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];
        let frame3 = vec![3u8; 8];

        let mut recv_stream = RecvStreamInner::<TestStreamWaker>::with_data(&frame1, 0, false);
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

        let mut recv_stream = RecvStreamInner::<TestStreamWaker>::with_data(&frame1, 0, false);
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

        let mut recv_stream = RecvStreamInner::<TestStreamWaker>::with_data(&frame1, 0, false);
        assert!(recv_stream.process(16, 8, true, &frame3).is_ok());
        assert!(recv_stream.process(8, 9, false, &frame2).is_err());
    }

    #[test]
    fn stream_initiated_with_gap() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];
        let frame3 = vec![3u8; 8];

        let mut recv_stream = RecvStreamInner::<TestStreamWaker>::with_data(&frame2, 8, false);
        assert!(recv_stream.process(0, 8, false, &frame1).is_ok());
        assert!(recv_stream.process(16, 8, true, &frame3).is_ok());
    }

    #[test]
    fn index_map_preserves_order_by_offset() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];
        let frame3 = vec![3u8; 8];

        let mut recv_stream = RecvStreamInner::<TestStreamWaker>::with_data(&frame1, 0, false);
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

        let mut recv_stream = RecvStreamInner::<TestStreamWaker>::with_data(&frame1, 0, false);
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
    fn recv_stream_read_twice() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];

        let mut recv_stream = RecvStreamInner::<TestStreamWaker>::with_data(&frame1, 0, false);
        assert!(recv_stream.process(8, 8, true, &frame2).is_ok());

        let output = [1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2];
        let mut result = [0u8; 16];

        let size1 = recv_stream.consume(&mut result[..4]).unwrap();
        let size2 = recv_stream.consume(&mut result[4..]).unwrap();

        assert_eq!(size1, 4);
        assert_eq!(size2, 12);
        assert_eq!(output, result);
    }

    #[test]
    fn recv_stream_read_with_gap() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];
        let frame3 = vec![3u8; 8];

        let mut result = [0u8; 24];

        let mut recv_stream = RecvStreamInner::<TestStreamWaker>::with_data(&frame1, 0, false);
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

        let mut recv_stream = RecvStreamInner::<TestStreamWaker>::with_data(&frame1, 0, false);
        assert!(recv_stream.process(8, 8, false, &frame2).is_ok());
        assert!(recv_stream.reset(0x00, 16).is_ok());
    }

    #[test]
    fn recv_stream_reset_invalid_final_size_too_large() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];

        let mut recv_stream = RecvStreamInner::<TestStreamWaker>::with_data(&frame1, 0, false);
        assert!(recv_stream.process(8, 8, true, &frame2).is_ok());
        assert!(recv_stream.reset(0x00, 17).is_err());
    }

    #[test]
    fn recv_stream_reset_invalid_final_size_too_small() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];

        let mut recv_stream = RecvStreamInner::<TestStreamWaker>::with_data(&frame1, 0, false);
        assert!(recv_stream.process(8, 8, false, &frame2).is_ok());
        assert!(recv_stream.reset(0x00, 15).is_err());
    }

    #[test]
    fn send_stream_emit() {
        let frame1 = vec![1u8; 8];
        let mut result = vec![0u8; 8];

        let mut send_stream = SendStreamInner::new(None);

        send_stream.append(&frame1, true).unwrap();

        assert_eq!(send_stream.length, 8);
        assert_eq!(send_stream.off, 0);

        let (size, fin) = send_stream.emit(&mut result, 0).unwrap();

        assert!(fin);
        assert_eq!(size, 8);
        assert_eq!(send_stream.off, 8);

        assert!(send_stream.pending.get(&0).is_some());
    }

    #[test]
    fn send_stream_emit_split_chunk() {
        let frame1 = vec![1u8; 8];
        let mut result = [0u8; 8];

        let mut send_stream = SendStreamInner::new(None);

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
    fn send_stream_reset() {
        let frame1 = vec![1u8; 8];
        let mut result = vec![0u8; 8];

        let mut send_stream = SendStreamInner::new(None);

        send_stream.append(&frame1, false).unwrap();

        send_stream.reset(0xf).unwrap();

        assert!(send_stream.pending.is_empty());

        //assert appending and emitting is disabled after reset
        assert!(send_stream.append(&frame1, true).is_err());
        assert!(send_stream.emit(&mut result, 0).is_err());
    }

    #[test]
    fn send_stream_readable() {
        let frame1 = vec![1u8; 8];
        let mut result = vec![0u8; 8];

        let mut send_stream = SendStreamInner::new(None);

        assert!(!send_stream.readable());

        send_stream.append(&frame1, true).unwrap();

        assert!(send_stream.readable());

        send_stream.emit(&mut result, 0).unwrap();

        assert!(!send_stream.readable());
    }
}
