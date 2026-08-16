use crate::{
    cc,
    connection::Connection,
    fc, terror,
    transport_parameters::{
        InitialMaxData, InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote,
        InitialMaxStreamDataUni, InitialMaxStreamsBidi, InitialMaxStreamsUni, TransportConfig,
        VarInt,
    },
    InnerEvent,
};

use std::{
    collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque},
    future,
    ops::Range,
    sync::Arc,
};

use octets::varint_len;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use tracing::{debug, trace, warn};

const STREAM_TYPE: u64 = 0x3;
const CLIENT_INIT_BIDI: u64 = 0x00;
const SERVER_INIT_BIDI: u64 = 0x01;
const CLIENT_INIT_UNI: u64 = 0x02;
const SERVER_INIT_UNI: u64 = 0x03;

// if peer stream seq upgrade is triggered, max_streams is increased by
const MAX_STREAMS_UPGRADE: u64 = 0x05;

// if less than said streams can be openend by peer, upgrade is triggered
const MAX_STREAMS_TRIGGER: u64 = 0x02;

/// crypto recv buffer limit for purpose built crypto stream
const CRYPTO_RECV_BUFFER_LIMIT: usize = 16 * 1024;

type StreamId = u64;
type StreamPriority = u8;

/// public struct for the RecvStream
pub struct RecvStream {
    pub id: StreamId,
    inner: Connection,
}

impl RecvStream {
    pub fn new(id: StreamId, inner: Connection) -> Self {
        Self { id, inner }
    }

    /// reads data from a stream into the provided buffer. If successfull, returns number of bytes
    /// read. Existing data in the buffer is overwritten. Returns [`None`] if the stream is finished
    /// or has been reset.
    pub async fn read(&self, buf: &mut [u8]) -> Result<Option<usize>, terror::Error> {
        future::poll_fn(|cx| self.inner.poll_recv(cx, &self.id, buf)).await
    }

    pub async fn read_exact(&self, buf: &mut [u8]) -> Result<(), terror::Error> {
        let mut filled = 0;
        while filled < buf.len() {
            match self.read(&mut buf[filled..]).await? {
                Some(n) => filled += n,
                None => {
                    return Err(terror::Error::stream_error(
                        "stream finished before read_exact filled the buffer",
                    ))
                }
            }
        }
        Ok(())
    }
}

/// public struct for the SendStream
pub struct SendStream {
    pub id: StreamId,
    inner: Connection,
}

impl SendStream {
    pub fn new(id: StreamId, inner: Connection) -> Self {
        Self { id, inner }
    }

    /// writes data to a send stream. returns the number of bytes written. due to local buffer
    /// limits it is not guaranteed that all data will be appended. writing to a finished or reset
    /// stream returns an error. returns when bytes are appended
    pub async fn write(&self, buf: &[u8], fin: bool) -> Result<usize, terror::Error> {
        future::poll_fn(|cx| self.inner.poll_send(cx, &self.id, buf, fin)).await
    }

    /// can be used to wait for a stream to be finished. a send stream is considered finished if the
    /// fin bit has been set and all data has been sent and acked
    pub async fn finish(&self) -> Result<(), terror::Error> {
        future::poll_fn(|cx| self.inner.poll_finished(cx, &self.id)).await
    }
}

// stream manager config for initial flow control and stream limits
// TODO add config param for how many incoming streams may be held ready at any time (or data of
// unconsumed streams)
pub struct StreamManagerConfig {
    /// initial limits for our recv streams sent in our transport parameters
    initial_inbound_limits: fc::InitialStreamDataLimits,

    /// initial amount of data allowed to be received
    initial_max_data: u64,

    /// initial amount of bidirectional streams the peer can initiate
    initial_max_bidi_streams: u64,

    /// initial amount of unirectional streams the peer can initiate
    initial_max_uni_streams: u64,

    /// caps the local buffer size of every send stream
    max_send_buffer: usize,
}

impl StreamManagerConfig {
    pub fn new(
        initial_max_bidi_streams: u64,
        initial_max_uni_streams: u64,
        max_send_buffer: usize,
    ) -> Self {
        let initial_inbound_limits = fc::InitialStreamDataLimits {
            max_stream_data_bidi_local: fc::INITIAL_MAX_DATA_BIDI_STREAM,
            max_stream_data_bidi_remote: fc::INITIAL_MAX_DATA_BIDI_STREAM,
            max_stream_data_uni: fc::INITIAL_MAX_DATA_UNI_STREAM,
        };

        Self {
            initial_inbound_limits,
            initial_max_data: fc::INITIAL_MAX_DATA,
            initial_max_bidi_streams,
            initial_max_uni_streams,
            max_send_buffer,
        }
    }
}

enum AckOutcome {
    Finished,
    Writable,
    None,
}

/// stores and manages streams for connection
pub struct StreamManager {
    /// all streams, sorted by inbound and outbound
    outbound: FxHashMap<StreamId, SendStreamInner>,
    inbound: FxHashMap<StreamId, RecvStreamInner>,

    /// [client init bidi, server init bidi, client init uni, server init uni]
    counts: [u64; 4],

    /// peer and local stream limits in the above sequence
    limits: [u64; 4],

    /// indicates if we hit the peers limits while opening a stream, triggering a STREAMS_BLOCKED
    blocked_pending: [Option<u64>; 2], // 0 = bidi, 1 = uni

    /// holds unconsumed stream ids in binary min heap. incoming path only requires
    /// .push() call which is O(1) and querying is O(log n) which is neglegible because it is only
    /// done by the application and does not impact packet processing times.
    ready: [BinaryHeap<std::cmp::Reverse<u64>>; 4],

    /// in case [`StreamManager::initiate`] it called but the peers stream limits currently do not
    /// allow for another stream this is flipped to true. once the limit is increased an event is
    /// emitted. or, in case [`StreamManager::poll_ready`] it called but no new stream is ready,
    /// this is also flipped to true. once a new stream is then accepted an event is emitted
    waiters: [bool; 4],

    /// keeps track of outbound streams which have data to write. Key for the tree is a tuple
    /// of StreamPriority & StreamId. Tuples implement ord from left to right, so first stream
    /// id has highest priority (1) and multiple streams with the same priority are ordered by
    /// acending id
    outbound_ready: BTreeSet<(StreamPriority, StreamId)>,

    /// holds stream_ids which need an increase in their max_data
    pending_max_stream_data: VecDeque<StreamId>,

    /// initial limits from peers transport parameters for send streams
    initial_outbound_limits: fc::InitialStreamDataLimits,

    /// initial limits for our recv streams sent in our transport parameters
    initial_inbound_limits: fc::InitialStreamDataLimits,

    /// caps the local buffer size of every send stream
    max_send_buffer: usize,

    /// the maximum amount of data we are allowed to send. set by peer
    max_data: usize,

    /// connection level flow control for our receiving end
    flow_control: fc::FlowControl,

    /// bytes sent
    sent: usize,

    /// used as least significant bit in stream ids. distinguishes between client (0x00) and server
    /// (0x01)
    local: u8,
}

impl StreamManager {
    pub fn new(config: StreamManagerConfig, local: u8) -> Self {
        assert!(local == 0x00 || local == 0x01, "local must be 0x00 or 0x01");

        // set inbound limits
        let mut limits = [0u64; 4];
        limits[(local ^ 0x01) as usize] = config.initial_max_bidi_streams;
        limits[((local ^ 0x01) as usize) | 0x02] = config.initial_max_uni_streams;

        Self {
            inbound: FxHashMap::default(),
            outbound: FxHashMap::default(),
            counts: [0; 4],
            limits,
            blocked_pending: [None; 2],
            ready: [(); 4].map(|_| BinaryHeap::with_capacity(16)),
            waiters: [false; 4],
            outbound_ready: BTreeSet::new(),
            pending_max_stream_data: VecDeque::new(),
            initial_outbound_limits: fc::InitialStreamDataLimits::default(),
            initial_inbound_limits: config.initial_inbound_limits.clone(),
            max_send_buffer: config.max_send_buffer,
            max_data: 0,
            flow_control: fc::FlowControl::with_max_data(
                config.initial_max_data,
                fc::MAX_WINDOW_CONNECTION,
            ),
            sent: 0,
            local,
        }
    }

    pub fn has_send_stream(&self, id: &StreamId) -> bool {
        self.outbound.contains_key(id)
    }

    pub fn has_pending(&self) -> bool {
        !self.outbound_ready.is_empty()
            || !self.pending_max_stream_data.is_empty()
            || self.bidi_streams_blocked().is_some()
            || self.uni_streams_blocked().is_some()
    }

    pub fn max_data(&self) -> u64 {
        self.flow_control.max_data()
    }

    pub fn nearly_full(&self) -> bool {
        self.flow_control.nearly_full()
    }

    // fills flow control values into local transport_parameters config
    pub fn fill_initial_local_tpc(
        &mut self,
        tpc: &mut TransportConfig,
    ) -> Result<(), terror::Error> {
        tpc.initial_max_data = InitialMaxData::try_from(VarInt::from(fc::INITIAL_MAX_DATA))?;

        tpc.initial_max_streams_bidi = InitialMaxStreamsBidi::try_from(VarInt::from(
            self.limits[(self.local ^ 0x01) as usize],
        ))?;
        tpc.initial_max_streams_uni = InitialMaxStreamsUni::try_from(VarInt::from(
            self.limits[(!self.local as usize) & 0x02],
        ))?;

        tpc.initial_max_stream_data_bidi_remote = InitialMaxStreamDataBidiRemote::try_from(
            VarInt::from(fc::INITIAL_MAX_DATA_BIDI_STREAM),
        )?;
        tpc.initial_max_stream_data_bidi_local = InitialMaxStreamDataBidiLocal::try_from(
            VarInt::from(fc::INITIAL_MAX_DATA_BIDI_STREAM),
        )?;
        tpc.initial_max_stream_data_uni =
            InitialMaxStreamDataUni::try_from(VarInt::from(fc::INITIAL_MAX_DATA_UNI_STREAM))?;

        Ok(())
    }

    // if bidi streams are blocked, returns sequence number they are blocked at
    pub fn bidi_streams_blocked(&self) -> Option<u64> {
        self.blocked_pending[0]
    }

    // if uni streams are blocked, returns sequence number they are blocked at
    pub fn uni_streams_blocked(&self) -> Option<u64> {
        self.blocked_pending[1]
    }

    // max amount of bidi streams we are allowed to open. set by peer
    pub fn set_max_streams_bidi(&mut self, max_streams_bidi: u64) -> Option<InnerEvent> {
        self.limits[self.local as usize] = max_streams_bidi;
        if self.waiters[self.local as usize] {
            self.waiters[self.local as usize] = false;
            return Some(InnerEvent::StreamOpenable(true));
        }
        None
    }

    // max amount of uni streams we are allowed to open. set by peer
    pub fn set_max_streams_uni(&mut self, max_streams_uni: u64) -> Option<InnerEvent> {
        self.limits[(self.local | 0x02) as usize] = max_streams_uni;
        if self.waiters[(self.local | 0x02) as usize] {
            self.waiters[(self.local | 0x02) as usize] = false;
            return Some(InnerEvent::StreamOpenable(false));
        }
        None
    }

    // max amount of data we are allowed to send over the whole connection. set by peer
    pub fn set_max_data(&mut self, max_data: u64) {
        self.max_data = max_data as usize;
    }

    // max amount of data we are allowed to send over the specified stream. set by peer
    pub fn set_max_stream_data(
        &mut self,
        max_data: u64,
        stream_id: StreamId,
    ) -> Result<(), terror::Error> {
        if let Some(ss_id) = self.outbound.get_mut(&stream_id) {
            ss_id.set_max_data(max_data);
            return Ok(());
        }

        // if we receive a MAX_STREAM_DATA for a receive only stream, we return a
        // stream_state_error
        Err(terror::Error::quic_transport_error(
            "received MAX_STREAM_DATA frame for receive only stream",
            terror::QuicTransportError::StreamStateError,
        ))
    }

    // used to set limits from peer transport_parameters
    pub fn set_initial_data_limits(
        &mut self,
        initial_max_stream_data_bidi_local: u64,
        initial_max_stream_data_bidi_remote: u64,
        initial_max_stream_data_uni: u64,
    ) {
        self.initial_outbound_limits.max_stream_data_bidi_local =
            initial_max_stream_data_bidi_local;
        self.initial_outbound_limits.max_stream_data_bidi_remote =
            initial_max_stream_data_bidi_remote;
        self.initial_outbound_limits.max_stream_data_uni = initial_max_stream_data_uni;
    }

    pub fn upgrade_max_data(&mut self) -> u64 {
        // adjust window size without throttling for connection
        self.flow_control.adjust_window_size(false);

        self.flow_control.poll_max_data()
    }

    // upgrade max stream data per stream
    pub fn upgrade_max_stream_data(
        &mut self,
        buf: &mut octets::OctetsMut,
    ) -> Result<(), terror::Error> {
        while let Some(rs_id) = self.pending_max_stream_data.front() {
            if let Some(rs) = self.inbound.get_mut(rs_id) {
                // only upgrade max data if enough space is left in buffer, i.e.
                // id len + max max_data + 1 (frame code)
                if buf.cap()
                    >= 0x01 + varint_len(rs.max_data() + fc::MAX_WINDOW_STREAM) + varint_len(*rs_id)
                {
                    let n_md = rs.upgrade_max_data();
                    let start = buf.off();

                    buf.put_varint(0x11)?;
                    buf.put_varint(*rs_id)?;
                    buf.put_varint(n_md)?;

                    tracing::trace!(
                        receive_stream_id = rs_id,
                        new_max_data = n_md,
                        "encoded MAX_STREAM_DATA frame: {:?}",
                        &buf.buf()[start..buf.off()]
                    );

                    let _ = self.pending_max_stream_data.pop_front();
                } else {
                    break;
                }
            }
        }

        Ok(())
    }

    // check our limit we send to the peer. if we have less than MAX_STREAMS_TRIGGER remaining
    // streams, we encode an MAX_STREAMS frame and add MAX_STREAMS_UPGRADE streams to the limit
    pub fn upgrade_peer_stream_limits(
        &mut self,
        buf: &mut octets::OctetsMut,
    ) -> Result<(), terror::Error> {
        let crnt_bidi_limit = self.limits[(self.local ^ 0x01) as usize];
        let crnt_bidi_seq = self.counts[(self.local ^ 0x01) as usize];

        // MAYBE change to something more sophisticated
        // buf.cap implicitly checks for +1 via > for frame header
        if crnt_bidi_limit - crnt_bidi_seq < MAX_STREAMS_TRIGGER
            && buf.cap() > varint_len(crnt_bidi_limit + MAX_STREAMS_UPGRADE)
        {
            let start = buf.off();
            buf.put_varint(0x12)?;
            buf.put_varint(crnt_bidi_limit + MAX_STREAMS_UPGRADE)?;
            self.limits[(self.local ^ 0x01) as usize] += MAX_STREAMS_UPGRADE;
            tracing::trace!(
                new_limit = self.limits[(self.local ^ 0x01) as usize],
                "encoded MAX_STREAMS (bidi) frame: {:?}",
                &buf.buf()[start..buf.off()]
            );
        }

        let crnt_uni_limit = self.limits[(self.local ^ 0x01 | 0x02) as usize];
        let crnt_uni_seq = self.counts[(self.local ^ 0x01 | 0x02) as usize];

        // buf.cap implicitly checks for +1 via > for frame header
        if crnt_uni_limit - crnt_uni_seq < MAX_STREAMS_TRIGGER
            && buf.cap() > varint_len(crnt_uni_limit + MAX_STREAMS_UPGRADE)
        {
            let start = buf.off();
            buf.put_varint(0x13)?;
            buf.put_varint(crnt_uni_limit + MAX_STREAMS_UPGRADE)?;
            self.limits[(self.local ^ 0x01 | 0x02) as usize] += MAX_STREAMS_UPGRADE;
            tracing::trace!(
                new_limit = self.limits[(self.local ^ 0x01 | 0x02) as usize],
                "encoded MAX_STREAMS (uni) frame: {:?}",
                &buf.buf()[start..buf.off()]
            );
        }

        Ok(())
    }

    // polls for specific stream type. if no ready stream was found, save callback
    pub fn poll_ready(&mut self, stream_t: u64) -> Option<StreamId> {
        let stream_t: usize = stream_t as usize;
        if let Some(id) = self.ready[stream_t].pop() {
            return Some(id.0);
        }

        // no ready stream was found, save waiting flag
        self.waiters[stream_t] = true;

        None
    }

    // creates a new stream with a given stream type and stream sequence. does not error check
    fn create(
        &mut self,
        stream_t: u64,
        stream_s: u64,
        priority: Option<StreamPriority>,
        local: bool,
        max_data_send: u64,
        max_data_recv: u64,
    ) -> StreamId {
        if stream_s >= self.counts[stream_t as usize] {
            self.counts[stream_t as usize] = stream_s + 1;
        }

        let stream_id = stream_t | (stream_s << 2);

        if stream_t == CLIENT_INIT_BIDI || stream_t == SERVER_INIT_BIDI {
            self.inbound
                .insert(stream_id, RecvStreamInner::new(priority, max_data_recv));
            self.outbound.insert(
                stream_id,
                SendStreamInner::new(priority, max_data_send, self.max_send_buffer),
            );
        } else if (stream_t == CLIENT_INIT_UNI || stream_t == SERVER_INIT_UNI) && local {
            // if stream is unidirectional and created locally it is always outbound
            self.outbound.insert(
                stream_id,
                SendStreamInner::new(priority, max_data_send, self.max_send_buffer),
            );
        } else if (stream_t == CLIENT_INIT_UNI || stream_t == SERVER_INIT_UNI) && !local {
            // if it is not locally created it must be inbound
            self.inbound
                .insert(stream_id, RecvStreamInner::new(priority, max_data_recv));
        }

        debug!("created stream {{id: {stream_id}}}");

        stream_id
    }

    // issues a new stream id and creates a new stream
    pub fn initiate(
        &mut self,
        stream_t: u64,
        priority: Option<StreamPriority>,
    ) -> Option<StreamId> {
        // deduct stream type
        let stream_t = (stream_t | (self.local as u64)) as usize;

        // get next sequence number
        let sequence = self.counts[stream_t];

        // check peer's limits
        let limit = self.limits[stream_t];
        if limit == 0 || sequence > limit - 1 {
            tracing::warn!("reached stream limit for stream type {stream_t}");

            if self.blocked_pending[stream_t >> 1] != Some(limit) {
                self.blocked_pending[stream_t >> 1] = Some(limit);
            }

            self.waiters[stream_t] = true;
            return None;
        }

        // set initial recv and send limit for peer created inbound stream, either bidi or uni
        let (initial_max_data_send, initial_max_data_recv) = match (stream_t & 0x02) == 0 {
            false => (self.initial_outbound_limits.max_stream_data_uni, 0),
            true => (
                self.initial_outbound_limits.max_stream_data_bidi_remote,
                self.initial_inbound_limits.max_stream_data_bidi_local,
            ),
        };

        Some(self.create(
            stream_t as u64,
            sequence,
            priority,
            true,
            initial_max_data_send,
            initial_max_data_recv,
        ))
    }

    // handles any incoming stream frame
    pub fn incoming(
        &mut self,
        stream_id: u64,
        offset: u64,
        length: u64,
        fin: bool,
        data: &[u8],
    ) -> Result<Option<InnerEvent>, terror::Error> {
        // validate against flow control limit. use current len as off
        self.flow_control
            .validate(self.flow_control.len(), length)?;

        if let Some(rs) = self.inbound.get_mut(&stream_id) {
            if rs.process(offset, length, fin, data)? {
                self.pending_max_stream_data.push_back(stream_id);

                // check if someone is waiting on that stream for more data
                if rs.blocked_on_read {
                    rs.blocked_on_read = false;
                    return Ok(Some(InnerEvent::StreamReadable(stream_id)));
                }
            }
            return Ok(None);
        }

        if (stream_id & 0x01) == self.local as u64 {
            return Err(terror::Error::stream_error("local stream cant be incoming"));
        }

        let sequence = stream_id >> 2;
        let stream_t = stream_id & STREAM_TYPE;

        // limit 0 means no streams but id 0 is first stream id
        let limit = self.limits[stream_t as usize];
        if limit == 0 || sequence > limit - 1 {
            return Err(terror::Error::quic_transport_error(
                "incoming stream exceeds stream limit",
                terror::QuicTransportError::StreamLimitError,
            ));
        }

        // set initial recv and send limit for peer created inbound stream, either bidi or uni
        let (initial_max_data_send, initial_max_data_recv) = match (stream_id & 0x10) == 0x00 {
            false => (0, self.initial_inbound_limits.max_stream_data_uni),
            true => (
                self.initial_outbound_limits.max_stream_data_bidi_local,
                self.initial_inbound_limits.max_stream_data_bidi_remote,
            ),
        };

        // because stream is incoming it cant be local
        self.create(
            stream_t,
            sequence,
            None,
            false,
            initial_max_data_send,
            initial_max_data_recv,
        );

        // unwrap is safe because stream was created
        let recv_s = self.inbound.get_mut(&stream_id).unwrap();
        if recv_s.process(offset, length, fin, data)? {
            self.pending_max_stream_data.push_back(stream_id);
        }

        // save stream as ready
        let stream_t = (stream_id & STREAM_TYPE) as usize;
        self.ready[stream_t].push(std::cmp::Reverse(stream_id));

        // invoke callback if present
        let mut event = None;
        if self.waiters[stream_t] {
            self.waiters[stream_t] = false;
            event = Some(InnerEvent::StreamAcceptable(stream_id & 0x02 == 0));
        }

        Ok(event)
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
    // TODO we need a way to read an exact amount of bytes
    pub fn consume(
        &mut self,
        stream_id: &StreamId,
        buf: &mut [u8],
    ) -> Result<Option<usize>, terror::Error> {
        let stream = match self.inbound.get_mut(stream_id) {
            Some(s) => s,
            None => return Err(terror::Error::invalid_stream("invalid stream id")),
        };

        let read = stream.consume(buf);

        if let Some(0) = read {
            // if there is nothing to read we register the stream_id to be waiting
            stream.blocked_on_read = true;
        }

        Ok(read)
    }

    // modifies a streams priority, a possible entry into outbound ready is updated
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

    // fills the buffer with stream frames. encodes (STREAM_)DATA_BLOCKED frames implicitly
    // returns size written in bytes over all stream and the cc info in SentFrames via out param
    pub fn emit_fill(
        &mut self,
        buf: &mut [u8],
        out: &mut SmallVec<[cc::SentFrame; 2]>,
    ) -> Result<usize, terror::Error> {
        let mut written = 0;
        let mut remaining = buf.len();

        while remaining > 0 {
            let b = self.emit_single(&mut buf[written..], out)?;

            if b == 0 {
                break;
            }

            remaining -= b;
            written += b;
        }

        // DATA BLOCKED
        let data_blocked_len = varint_len(0x14) + varint_len(self.max_data as u64);
        if self.max_data == self.sent && data_blocked_len <= buf.len() - written {
            trace!("connection data blocked at {}", self.max_data);

            let mut octets = octets::OctetsMut::with_slice(&mut buf[written..]);
            octets.put_varint(0x14)?;
            octets.put_varint(self.max_data as u64)?;

            written += data_blocked_len;
        }

        Ok(written)
    }

    // emits a single stream frame onto the buffer from the stream with the highest priority i.e.
    // the lowest number. if two streams have the same priority, the lower stream id is prioritised
    pub fn emit_single(
        &mut self,
        buf: &mut [u8],
        out: &mut SmallVec<[cc::SentFrame; 2]>,
    ) -> Result<usize, terror::Error> {
        // return if we reached flow control limit of peer
        if self.max_data <= self.sent {
            return Ok(0);
        }

        let mut octets = octets::OctetsMut::with_slice(buf);

        // take first ready stream with outbound data
        let Some((p, ss_id)) = self.outbound_ready.first() else {
            return Ok(0);
        };

        let Some(ss) = self.outbound.get_mut(ss_id) else {
            return Err(terror::Error::stream_error(format!(
                "outbound stream (id: {}) with ready data does not exist",
                ss_id
            )));
        };

        if ss.data_blocked() {
            //TODO somehow remember if data_blocked sent to prevent spam
            trace!("stream {} data blocked", *ss_id);
            return ss.stream_data_blocked_encode(*ss_id, &mut octets);
        }

        let ss_sent = ss.off;

        // peek current offset and relative length of stream that is writeable
        let Some((stream_off, rel_length)) = ss.peek() else {
            return Ok(0);
        };

        // calculate stram frame overhead
        let mut overhead = 1 + varint_len(*ss_id);

        if stream_off > 0 {
            overhead += varint_len(stream_off);
        }

        // if there not enough space for frame overhead plus at least one byte of data, return
        if overhead + 1 > octets.len() {
            debug!("buffer too small for stream frame");
            return Err(terror::Error::buffer_size_error(
                "insufficient buffer size for stream frame",
            ));
        }

        let mut stream_header: u8 = 0x08;
        let (mut stream_header_raw, mut rest) = octets.split_at(1)?;

        rest.put_varint(*ss_id)?;

        if stream_off > 0 {
            stream_header |= 0x04; // OFF
            rest.put_varint(stream_off)?;
        }

        let stream_room = ss.max_data.saturating_sub(ss.off as u64);
        let fc_len = rel_length
            .min(self.max_data - self.sent)
            .min(stream_room as usize);

        // edge case where length field encoding length plus data length is exactly the buffer
        // length, length field must be included. should be reinvestigated but I cant think of any
        // other or betteror better solution right now
        if rest.cap() >= fc_len + varint_len(fc_len as u64) {
            // length field has to be included
            stream_header |= 0x02;
            overhead += rest.put_varint(fc_len as u64)?.len();
        }

        // compute flow control send limit
        let fc_limit = std::cmp::min(rest.cap(), fc_len);

        let Some((off, len, fin)) = ss.emit(&mut rest.as_mut()[..fc_limit]) else {
            return Ok(0);
        };

        if fin {
            stream_header |= 0x01;
        }

        // add to tracking of cc
        out.push(cc::SentFrame::Stream {
            id: *ss_id,
            off,
            len: len as u32,
            fin,
        });

        // write stream header last
        stream_header_raw.put_u8(stream_header)?;

        if !ss.readable() {
            self.outbound_ready.remove(&(*p, *ss_id));
        }

        // use difference to calculate "actual" emitted bytes without retransmits
        self.sent += ss.off - ss_sent;

        Ok(len + overhead)
    }

    pub fn ack(&mut self, id: StreamId, off: u64, len: u32) -> Option<InnerEvent> {
        let outcome = self.outbound.get_mut(&id)?.ack(off, len);
        match outcome {
            AckOutcome::Finished => {
                self.outbound.remove(&id);
                tracing::trace!(stream_id = id, "stream finished");
                Some(InnerEvent::StreamFinished(id))
            }
            AckOutcome::Writable => Some(InnerEvent::StreamWritable(id)),
            AckOutcome::None => None,
        }
    }

    pub fn lost(&mut self, id: StreamId, off: u64, len: u32) {
        if let Some(ss) = self.outbound.get_mut(&id) {
            ss.lost(off, len);
            self.outbound_ready.insert((ss.prio, id));
        }
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

struct SendStreamInner {
    // data chunks ordered in outgoing direction
    data: VecDeque<Chunk>,

    // keeps track of pending stream data via offset of sent frames
    inflight: BTreeMap<u64, Chunk>,

    // application error code in case stream is reset
    apec: Option<u64>,

    // stream priority, lower is better
    prio: StreamPriority,

    // current length of all stream data. if fin is set that is the final size
    length: usize,

    // current offset of internal data being sent
    off: usize,

    // peer limit
    max_data: u64,

    // finalized flag
    fin: bool,

    /// in case [`SendStreamInner::append`] is called on a SendStream with no available space for
    /// additional data. if more space becomes available, an event will be emitted
    blocked_on_write: bool,

    /// total bytes acknowledged
    acked: usize,

    /// cap on local max send buffer size
    max_buffer: usize,
}

impl SendStreamInner {
    fn new(priority: Option<StreamPriority>, max_data: u64, max_buffer: usize) -> Self {
        Self {
            data: VecDeque::new(),
            inflight: BTreeMap::new(),
            apec: None,
            prio: priority.unwrap_or(u8::MAX),
            length: 0,
            off: 0,
            max_data,
            fin: false,
            blocked_on_write: false,
            acked: 0,
            max_buffer,
        }
    }

    #[inline]
    fn outstanding(&self) -> usize {
        self.length - self.acked
    }

    pub fn set_max_data(&mut self, max_data: u64) {
        self.max_data = max_data;
    }

    pub fn data_blocked(&self) -> bool {
        self.max_data == self.off as u64
    }

    pub fn stream_data_blocked_encode(
        &self,
        id: StreamId,
        buf: &mut octets::OctetsMut,
    ) -> Result<usize, terror::Error> {
        let start = buf.off();
        buf.put_varint(0x15)?;
        buf.put_varint(id)?;
        buf.put_varint(self.max_data)?;
        Ok(buf.off() - start)
    }

    fn readable(&self) -> bool {
        !self.data.is_empty()
    }

    // peeks sendable data to be able to build stream frame. returns (off, rel_len)
    fn peek(&self) -> Option<(u64, usize)> {
        let first = self.data.front()?;
        let start = first.off();
        let mut end = start + first.len() as u64;

        for c in self.data.iter().skip(1) {
            if c.off() != end {
                break;
            }
            end += c.len() as u64;
        }

        Some((start, (end - start) as usize))
    }

    // emits data to be sent, returns (frame_offset, len, fin)
    fn emit(&mut self, buf: &mut [u8]) -> Option<(u64, usize, bool)> {
        let mut written = 0;
        let mut fin = false;
        let mut next = self.data.front()?.off();
        let frame_off = next;

        while written < buf.len() {
            let Some(front) = self.data.front() else {
                break;
            };

            // a gap or no more buffer space ends the frame
            let room = buf.len() - written;
            if front.off() != next || room == 0 {
                break;
            }

            let mut chunk = self.data.pop_front().unwrap();
            if chunk.is_empty() {
                continue;
            }

            let to_write = room.min(chunk.len());
            if to_write < chunk.len() {
                let rest = chunk.split_at(to_write);
                self.data.push_front(rest);
            }

            buf[written..written + to_write].copy_from_slice(&chunk[..to_write]);

            fin = chunk.fin;
            next += to_write as u64;
            written += to_write;
            self.inflight.insert(chunk.off(), chunk);
        }

        if written == 0 {
            return None;
        }
        self.off = self.off.max(next as usize);
        Some((frame_off, written, fin))
    }

    fn append(&mut self, data: &[u8], fin: bool) -> Result<usize, terror::Error> {
        if self.fin {
            return Err(terror::Error::stream_error(
                "cannot append to finalized or reset stream",
            ));
        }

        let room = self.max_buffer.saturating_sub(self.outstanding());
        let take = data.len().min(room);

        if take == 0 && !data.is_empty() {
            self.blocked_on_write = true;
            return Ok(0);
        }

        // partial write on fin set is not always final write
        let is_final = fin && take == data.len();
        self.data
            .push_back(Chunk::new(&data[..take], self.length as u64, is_final));
        self.length += take;
        self.fin |= is_final;

        Ok(take)
    }

    fn ack(&mut self, off: u64, len: u32) -> AckOutcome {
        let end = off + len as u64;
        let mut freed = 0usize;
        self.inflight
            .extract_if(off..end, |_, _| true)
            .for_each(|(_, c)| freed += c.len());
        self.acked += freed;

        if self.fin && self.acked == self.length && self.inflight.is_empty() {
            return AckOutcome::Finished;
        }

        if self.blocked_on_write && self.outstanding() < self.max_buffer {
            self.blocked_on_write = false;
            return AckOutcome::Writable;
        }

        AckOutcome::None
    }

    fn lost(&mut self, off: u64, len: u32) {
        let end = off + len as u64;
        let lost_chunks = self.inflight.extract_if(off..end, |_, _| true);
        for (_, chunk) in lost_chunks {
            let pos = self
                .data
                .iter()
                .position(|c| c.off() > chunk.off())
                .unwrap_or(self.data.len());
            self.data.insert(pos, chunk);
        }
    }

    fn reset(&mut self, apec: u64) -> Result<(), terror::Error> {
        if self.apec.is_some() {
            return Err(terror::Error::stream_error("cannot reset stream twice"));
        }

        self.apec = Some(apec);
        self.fin = true;
        self.off = self.length;

        self.data.clear();
        self.inflight.clear();

        Ok(())
    }
}

struct RecvStreamInner {
    /// data chunks ordered by their offset
    data: BTreeMap<u64, Chunk>,

    /// keeps track of gaps in received data. must be sorted at all times
    gaps: Vec<Range<u64>>,

    /// highest chunk offset into [`data`] that has been read
    max_read: u64,

    /// number of bytes that have been read from the stream
    bytes_read: usize,

    /// received stream frame with offset 0
    start_recv: bool,

    /// final size in case of reset
    final_size: Option<u64>,

    /// application error code received via reset
    apec: Option<u64>,

    /// stream priority
    prio: StreamPriority,

    /// stream level flow control for our receiving end
    flow_control: fc::FlowControl,

    /// in case [`RecvStreamInner::consume`] is called on a RecvStream with no ready data this is
    /// flipped to true. once new data for this stream arrives, an event is emitted
    blocked_on_read: bool,
}

impl RecvStreamInner {
    fn new(priority: Option<StreamPriority>, max_data: u64) -> Self {
        Self {
            data: BTreeMap::new(),
            gaps: Vec::new(),
            max_read: 0,
            bytes_read: 0,
            start_recv: false,
            final_size: None,
            apec: None,
            prio: priority.unwrap_or(u8::MAX),
            flow_control: fc::FlowControl::with_max_data(max_data, fc::MAX_WINDOW_STREAM),
            blocked_on_read: false,
        }
    }

    fn max_data(&self) -> u64 {
        self.flow_control.max_data()
    }

    // processes a single stream frame on the receiving end. should a gap emerge, incoming frames
    // which have not been received already are matched to those gaps via their offset. Per RFC 9000 sec.
    // 2.2: The data at a given offset MUST NOT change if it is sent multiple times; an endpoint MAY
    //   treat receipt of different data at the same offset within a stream as a connection error of
    //   type PROTOCOL_VIOLATION.
    // Therefore if a frame cannot be matched to a gap and no already received offset with matching
    // length exists, a Quic Transport Error is thrown. Returns wether flow control is nearly full.
    fn process(
        &mut self,
        offset: u64,
        length: u64,
        fin: bool,
        data: &[u8],
    ) -> Result<bool, terror::Error> {
        // check if offset and length match any already received chunks
        if let Some(chunk) = self.data.get(&offset) {
            if chunk.len == length as usize {
                return Ok(self.flow_control.nearly_full());
            }
        }

        // if the stream has been reset or an offset is higher than the final
        if self.apec.is_some() {
            return Err(terror::Error::stream_error(
                "cannot process frame: stream reset",
            ));
        }

        //if chunk with offset zero is received, we can emit
        self.start_recv = (offset == 0 && !self.start_recv) || (offset != 0 && self.start_recv);

        if let Some(fsize) = self.final_size {
            if offset > fsize {
                return Err(terror::Error::quic_transport_error(
                    "received offset higher than final size",
                    terror::QuicTransportError::FinalSizeError,
                ));
            }
        }

        // flow control validation, can return QuicTransportError
        self.flow_control.validate(offset, length)?;

        // check if offset and length match to any known gaps and insert chunk
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
                // insert lower gap as new range
                self.insert_gap(lower);
            }

            if !upper.is_empty() {
                // insert upper gap
                self.insert_gap(upper);
            }
        } else {
            //detect gaps in offset if offset is greater than next offset
            if let Some((last_off, last_chunk)) = self.data.last_key_value() {
                let succinct_offset = *last_off + last_chunk.len() as u64;
                if succinct_offset < offset {
                    self.insert_gap(succinct_offset..offset);
                }
            }
        }

        // insert chunk into sorted list
        self.data.insert(offset, Chunk::new(data, offset, fin));

        if fin {
            self.final_size = Some(offset + length);
        }

        Ok(self.flow_control.nearly_full())
    }

    fn upgrade_max_data(&mut self) -> u64 {
        self.flow_control.adjust_window_size(false);
        self.flow_control.poll_max_data()
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

        if final_size < self.flow_control.len() {
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
        /*if let Some(c) = self.callback.take() {
            c.invoke();
        }*/

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

                if self.data.contains_key(&next_off) {
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

/// purpose build send stream for crypto data
#[derive(Default)]
pub struct CryptoSend {
    /// data to send or retransmit
    pending: VecDeque<Chunk>,

    /// inflight data chunks, unordered
    inflight: SmallVec<[Chunk; 2]>,

    /// total length of stream data
    len: u64,
}

impl CryptoSend {
    pub fn wants_write(&self) -> bool {
        !self.pending.is_empty()
    }

    /// append data to crypto stream, data assumed to be not empty
    pub fn append(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let off = self.len;
        self.len += data.len() as u64;
        self.pending.push_back(Chunk::new(data, off, false));
    }

    fn contiguous_data(&self) -> (u64, usize) {
        let mut it = self.pending.iter();
        let Some(first) = it.next() else {
            return (0, 0);
        };

        let off = first.off();
        let mut end = first.max_off();
        let mut run = first.len();

        for c in it {
            if c.off() != end {
                break;
            }

            end = c.max_off();
            run += c.len();
        }
        (off, run)
    }

    /// emits a cryto frame onto the buffer
    pub fn emit(
        &mut self,
        buf: &mut octets::OctetsMut,
    ) -> Result<Option<(u64, usize)>, terror::Error> {
        let (off, run) = self.contiguous_data();
        if run == 0 {
            return Ok(None);
        }

        let hdr = 1 + varint_len(off) + varint_len(run as u64);
        if buf.cap() <= hdr {
            return Ok(None);
        }

        let payload = run.min(buf.cap() - hdr);
        if payload == 0 {
            return Ok(None);
        }

        let start = buf.off();

        buf.put_u8(0x06)?;
        buf.put_varint(off)?;
        buf.put_varint(payload as u64)?;

        let mut remaining = payload;
        while remaining > 0 {
            let mut chunk = self.pending.pop_front().expect("run overcounted");
            let take = remaining.min(chunk.len());

            if take < chunk.len() {
                let tail = chunk.split_at(take);
                self.pending.push_front(tail);
            }

            buf.put_bytes(&chunk[..take])?;
            remaining -= take;
            self.inflight.push(chunk);
        }

        tracing::trace!("encoded CRYPTO frame: {:?}", &buf.buf()[start..buf.off()]);

        Ok(Some((off, payload)))
    }

    /// requeues a Chunk into pending to be re-sent
    fn retransmit(&mut self, chunk: Chunk) {
        let pos = self
            .pending
            .iter()
            .position(|c| c.off() > chunk.off())
            .unwrap_or(self.pending.len());
        self.pending.insert(pos, chunk);
    }

    /// peer acked packet with a crypto frame
    pub fn ack(&mut self, off: u64, len: usize) {
        let end = off + len as u64;
        self.inflight.retain(|c| !(c.off() >= off && c.off() < end));
    }

    /// packet with a crypto frame has been lost, requeue for retransmit
    pub fn lost(&mut self, off: u64, len: usize) {
        let end = off + len as u64;
        let mut i = 0;

        while i < self.inflight.len() {
            if (off..end).contains(&self.inflight[i].off()) {
                let c = self.inflight.swap_remove(i);
                self.retransmit(c);
            } else {
                i += 1;
            }
        }
    }

    pub fn clear(&mut self) {
        self.pending.clear();
        self.inflight.clear();
    }
}

/// purpose build crypto receive stream
#[derive(Default)]
pub struct CryptoRecv {
    /// next in-order offset to feed to tls
    next: u64,

    /// out-of-order chunks sorted by offset ascending
    buffered: SmallVec<[Chunk; 2]>,

    /// out-of-order bytes
    buffered_bytes: usize,
}

impl CryptoRecv {
    /// the only entry point to the recv stream is the recv one. if data is in-order,
    /// pass it directly on and if its out-of-order buffer it. if a in-order frame
    /// arrives after and out-of-order one, everything is passed on
    pub fn recv(
        &mut self,
        offset: u64,
        data: &[u8],
        mut feed: impl FnMut(&[u8]) -> Result<(), terror::Error>,
    ) -> Result<(), terror::Error> {
        let end = offset + data.len() as u64;
        if end <= self.next {
            return Ok(());
        }

        if offset <= self.next {
            let skip = (self.next - offset) as usize;
            feed(&data[skip..])?;
            self.next = end;
            self.drain(&mut feed)?;
        } else {
            if self.buffered.iter().any(|c| c.off() == offset) {
                return Ok(());
            }

            if self.buffered_bytes + data.len() > CRYPTO_RECV_BUFFER_LIMIT {
                return Err(terror::Error::quic_transport_error(
                    "crypto receive buffer exceeded",
                    terror::QuicTransportError::CryptoBufferExceeded,
                ));
            }

            self.buffered_bytes += data.len();
            let pos = self.buffered.partition_point(|c| c.off() < offset);
            self.buffered.insert(pos, Chunk::new(data, offset, false));
        }
        Ok(())
    }

    fn drain(
        &mut self,
        feed: &mut impl FnMut(&[u8]) -> Result<(), terror::Error>,
    ) -> Result<(), terror::Error> {
        while let Some(front) = self.buffered.first() {
            if front.off() > self.next {
                break;
            }

            let chunk = self.buffered.remove(0);
            let off = chunk.off();
            self.buffered_bytes -= chunk.len();
            let cend = off + chunk.len() as u64;

            if cend <= self.next {
                continue;
            }

            let skip = (self.next - off) as usize;
            feed(&chunk[skip..])?;
            self.next = cend;
        }
        Ok(())
    }
}

/// single chunk of data
struct Chunk {
    /// read only data
    data: Arc<[u8]>,

    /// start in data, used to be able to split data without copying buffer
    start: usize,

    /// offset of chunk within stream
    off: u64,

    /// relative position in chunk while consuming
    pos: usize,

    /// chunk data length
    len: usize,

    /// if this chunk is the last one for the stream
    fin: bool,
}

impl Chunk {
    fn new(data: &[u8], off: u64, fin: bool) -> Self {
        Self {
            data: Arc::from(data),
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
    use fc::InitialStreamDataLimits;

    use super::*;

    impl Default for StreamManagerConfig {
        fn default() -> Self {
            let initial_inbound_limits = fc::InitialStreamDataLimits {
                max_stream_data_bidi_local: fc::INITIAL_MAX_DATA_BIDI_STREAM,
                max_stream_data_bidi_remote: fc::INITIAL_MAX_DATA_BIDI_STREAM,
                max_stream_data_uni: fc::INITIAL_MAX_DATA_UNI_STREAM,
            };

            Self {
                initial_inbound_limits,
                initial_max_data: 256 * 1024,
                initial_max_bidi_streams: 4,
                initial_max_uni_streams: 4,
                max_send_buffer: 256 * 1024,
            }
        }
    }

    impl RecvStreamInner {
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

            let mut map = BTreeMap::new();
            map.insert(off, chunk);

            if fin {
                final_size = Some(data.len() as u64);
            }

            let mut flow_control = fc::FlowControl::with_max_data(1024, fc::MAX_WINDOW_CONNECTION);
            flow_control.validate(off, data.len() as u64).unwrap();

            Self {
                data: map,
                gaps,
                max_read: 0,
                bytes_read: 0,
                start_recv,
                final_size,
                apec: None,
                prio: u8::MAX,
                flow_control,
                blocked_on_read: false,
            }
        }
    }

    #[test]
    fn stream_manager_create_as_server() {
        let config = StreamManagerConfig::default();
        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);
        sm.set_max_streams_bidi(2);
        sm.set_max_streams_uni(2);

        let bidi1 = sm.initiate(0x00, None).unwrap();
        let bidi2 = sm.initiate(0x00, None).unwrap();

        let uni1 = sm.initiate(0x02, None).unwrap();
        let uni2 = sm.initiate(0x02, None).unwrap();

        assert_eq!(bidi1, 0x01);
        assert_eq!(bidi2, 0x05);
        assert_eq!(uni1, 0x03);
        assert_eq!(uni2, 0x07);
    }

    #[test]
    fn stream_manager_create_stream_without_limit() {
        let config = StreamManagerConfig::default();
        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);
        sm.set_max_streams_bidi(1);
        sm.set_max_streams_uni(1);

        let bidi1 = sm.initiate(0x00, None).unwrap();
        let bidi2 = sm.initiate(0x00, None);

        let uni1 = sm.initiate(0x02, None).unwrap();
        let uni2 = sm.initiate(0x02, None);

        assert_eq!(bidi1, 0x01);
        assert!(bidi2.is_none());

        assert_eq!(uni1, 0x03);
        assert!(uni2.is_none());
    }

    #[test]
    fn stream_manager_create_as_client() {
        let config = StreamManagerConfig::default();
        let mut sm = StreamManager::new(config, rustls::Side::Client as u8);
        sm.set_max_streams_bidi(2);
        sm.set_max_streams_uni(2);

        let bidi1 = sm.initiate(0x00, None).unwrap();
        let bidi2 = sm.initiate(0x00, None).unwrap();

        let uni1 = sm.initiate(0x02, None).unwrap();
        let uni2 = sm.initiate(0x02, None).unwrap();

        assert_eq!(bidi1, 0x00);
        assert_eq!(bidi2, 0x04);
        assert_eq!(uni1, 0x02);
        assert_eq!(uni2, 0x06);
    }

    #[test]
    fn stream_manager_incoming_as_server() {
        let config = StreamManagerConfig {
            initial_inbound_limits: InitialStreamDataLimits {
                max_stream_data_bidi_remote: 8,
                max_stream_data_uni: 8,
                ..InitialStreamDataLimits::default()
            },
            initial_max_data: 1024,
            initial_max_bidi_streams: 3,
            initial_max_uni_streams: 1,
            max_send_buffer: 1024,
        };

        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        let bidi1 = 0x00;
        let bidi2 = 0x04;
        let bidi3 = 0x08;

        let uni1 = 0x02;

        sm.incoming(bidi3, 0, 8, true, &[1u8; 8]).unwrap();

        assert_eq!(sm.counts[0x00], 3);
        assert!(sm.inbound.contains_key(&bidi3));
        assert!(sm.outbound.contains_key(&bidi3));

        sm.incoming(bidi2, 0, 8, true, &[1u8; 8]).unwrap();

        assert!(sm.inbound.contains_key(&bidi2));
        assert!(sm.outbound.contains_key(&bidi2));

        sm.incoming(bidi1, 0, 8, true, &[1u8; 8]).unwrap();

        assert!(sm.inbound.contains_key(&bidi1));
        assert!(sm.outbound.contains_key(&bidi1));

        sm.incoming(uni1, 0, 8, true, &[1u8; 8]).unwrap();

        assert_eq!(sm.counts[0x02], 1);
        assert!(sm.inbound.contains_key(&uni1));
        assert!(!sm.outbound.contains_key(&uni1));
    }

    #[test]
    fn stream_manager_wrong_id_type_as_server() {
        let config = StreamManagerConfig::default();
        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        // server init bidi recv as server should fail
        let bidi = 0x05;

        assert!(sm.incoming(bidi, 0, 8, true, &[1u8; 8]).is_err());
    }

    #[test]
    fn stream_manager_emit_single() {
        let config = StreamManagerConfig::default();
        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        sm.set_max_streams_uni(1);
        sm.set_max_data(8);
        sm.set_initial_data_limits(0, 0, 8);

        let mut result = [0u8; 10];

        let send_stream = sm.initiate(0x02, None).unwrap();
        sm.append(send_stream, &[4u8; 8], true).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        assert!(sm.max_data >= sm.sent);

        let mut out = SmallVec::new();
        let written = sm.emit_single(&mut result, &mut out).unwrap();

        assert_eq!(result[0], 0x09);
        assert_eq!(result[1] as u64, send_stream);
        assert_eq!(result[2], 4);
        assert_eq!(result[8], 4);
        assert_eq!(written, 10);
        assert_eq!(
            out[0],
            cc::SentFrame::Stream {
                id: send_stream,
                off: 0,
                len: 8,
                fin: true
            }
        );
        assert!(sm.outbound_ready.is_empty());
        assert_eq!(sm.sent, 8);
        assert!(sm.max_data <= sm.sent);
    }

    #[test]
    fn stream_manager_incoming_stream_id_gap() {
        let config = StreamManagerConfig {
            initial_inbound_limits: InitialStreamDataLimits {
                max_stream_data_bidi_remote: 8,
                ..InitialStreamDataLimits::default()
            },
            initial_max_data: 1024,
            initial_max_bidi_streams: 3,
            initial_max_uni_streams: 0,
            max_send_buffer: 1024,
        };

        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        let bidi1 = 0x04;
        sm.incoming(bidi1, 0, 8, false, &[1u8; 8]).unwrap();

        let bidi2 = 0x08;
        sm.incoming(bidi2, 0, 8, false, &[2u8; 8]).unwrap();

        let first_id = sm.poll_ready(0x00).unwrap();

        let bidi0 = 0x00;
        sm.incoming(bidi0, 0, 8, false, &[0u8; 8]).unwrap();

        let second_id = sm.poll_ready(0x00).unwrap();

        assert_eq!(first_id, 0x04);
        assert_eq!(second_id, 0x00);
        assert_eq!(sm.ready[0x00].peek().unwrap().0, 0x08);
    }

    #[test]
    fn stream_manager_poll_ready() {
        let config = StreamManagerConfig {
            initial_inbound_limits: InitialStreamDataLimits {
                max_stream_data_bidi_remote: 8,
                ..InitialStreamDataLimits::default()
            },
            initial_max_data: 1024,
            initial_max_bidi_streams: 1,
            initial_max_uni_streams: 0,
            max_send_buffer: 1024,
        };

        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        let bidi1 = 0x00;
        sm.incoming(bidi1, 0, 8, true, &[1u8; 8]).unwrap();

        assert_eq!(sm.ready[0x00].peek().unwrap().0, 0x00);

        let id = sm.poll_ready(0x00).unwrap();

        assert_eq!(id, 0x00);
        assert!(sm.ready[0x00].is_empty());
    }

    #[test]
    fn stream_manager_poll_ready_multiple() {
        let config = StreamManagerConfig {
            initial_inbound_limits: InitialStreamDataLimits {
                max_stream_data_bidi_remote: 8,
                ..InitialStreamDataLimits::default()
            },
            initial_max_data: 1024,
            initial_max_bidi_streams: 2,
            initial_max_uni_streams: 0,
            max_send_buffer: 1024,
        };

        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        let bidi1 = 0x00;
        sm.incoming(bidi1, 0, 8, true, &[1u8; 8]).unwrap();

        assert_eq!(sm.ready[0x00].peek().unwrap().0, 0x00);

        let bidi2 = 0x04;
        sm.incoming(bidi2, 0, 8, true, &[2u8; 8]).unwrap();

        assert_eq!(sm.ready[0x00].peek().unwrap().0, 0x00);

        let id = sm.poll_ready(0x00).unwrap();

        assert_eq!(id, 0x00);
        assert_eq!(sm.ready[0x00].peek().unwrap().0, 0x04);
    }

    #[test]
    fn stream_manager_incoming_invokes_callback() {
        let config = StreamManagerConfig {
            initial_inbound_limits: InitialStreamDataLimits {
                max_stream_data_bidi_remote: 8,
                ..InitialStreamDataLimits::default()
            },
            initial_max_data: 1024,
            initial_max_bidi_streams: 1,
            initial_max_uni_streams: 0,
            max_send_buffer: 1024,
        };

        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        let id = sm.poll_ready(0x00);

        assert!(id.is_none());
        assert!(sm.waiters[0x00]);

        let bidi1 = 0x00;
        sm.incoming(bidi1, 0, 8, true, &[1u8; 8]).unwrap();

        assert_eq!(sm.ready[0x00].peek().unwrap().0, 0x00);
        assert!(!sm.waiters[0x00]);
    }

    #[test]
    fn stream_manager_emit_single_with_len() {
        let config = StreamManagerConfig::default();
        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        sm.set_max_streams_uni(1);
        sm.set_max_data(16);
        sm.set_initial_data_limits(0, 0, 16);

        let mut result = [0u8; 16];

        let send_stream = sm.initiate(0x02, None).unwrap();
        sm.append(send_stream, &[4u8; 8], true).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let mut out = SmallVec::new();
        let written = sm.emit_single(&mut result, &mut out).unwrap();

        assert_eq!(result[0], 0x0b);
        assert_eq!(result[1] as u64, send_stream);
        assert_eq!(result[2], 8); //LEN
        assert_eq!(result[3], 4); //DATA BEGIN
        assert_eq!(result[9], 4); //DATA END
        assert_eq!(written, 11);
        assert_eq!(
            out[0],
            cc::SentFrame::Stream {
                id: send_stream,
                off: 0,
                len: 8,
                fin: true
            }
        );
        assert!(sm.outbound_ready.is_empty());
        assert_eq!(sm.sent, 8);
    }

    #[test]
    fn stream_manager_emit_data_blocked() {
        let config = StreamManagerConfig::default();
        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        sm.set_max_streams_uni(1);
        sm.set_max_data(0);
        sm.set_initial_data_limits(0, 0, 0);

        let mut result = [0u8; 16];

        let send_stream = sm.initiate(0x02, None).unwrap();
        sm.append(send_stream, &[4u8; 8], true).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let mut out = SmallVec::new();
        let written = sm.emit_fill(&mut result, &mut out).unwrap();

        //DATA_BLOCKED frame
        assert_eq!(result[0], 0x14);
        assert_eq!(result[1], 0x00);

        assert_eq!(written, 2);
        assert_eq!(sm.sent, 0);
    }

    #[test]
    fn stream_manager_emit_data_blocked_while_emitting() {
        let config = StreamManagerConfig::default();
        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        sm.set_max_streams_uni(1);
        sm.set_max_data(4);
        sm.set_initial_data_limits(0, 0, 8);

        let mut result = [0u8; 16];

        let send_stream = sm.initiate(0x02, None).unwrap();
        sm.append(send_stream, &[2u8; 8], true).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let mut out = SmallVec::new();
        let written = sm.emit_fill(&mut result, &mut out).unwrap();

        //STREAM frame
        assert_eq!(result[0], 0x0a);
        assert_eq!(result[1] as u64, send_stream);
        assert_eq!(result[2], 4); //LEN
        assert_eq!(result[3], 2); //DATA BEGIN
        assert_eq!(result[6], 2); //DATA END

        //DATA_BLOCKED frame
        assert_eq!(result[7], 0x14);
        assert_eq!(result[8], 0x04);

        assert_eq!(written, 9);
        assert_eq!(sm.sent, 4);
    }

    #[test]
    fn stream_manager_emit_stream_data_blocked() {
        let config = StreamManagerConfig::default();
        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        sm.set_max_streams_uni(1);
        sm.set_max_data(16);
        sm.set_initial_data_limits(0, 0, 0);

        let mut result = [0u8; 16];

        let send_stream = sm.initiate(0x02, None).unwrap();
        sm.append(send_stream, &[4u8; 8], true).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let mut out = SmallVec::new();
        let written = sm.emit_single(&mut result, &mut out).unwrap();

        assert_eq!(result[0], 0x15);
        assert_eq!(result[1] as u64, send_stream);
        assert_eq!(result[2], 0); //BLOCKED_AT
        assert_eq!(written, 3);
        assert_eq!(sm.sent, 0);
    }

    #[test]
    fn stream_manager_emit_single_multiple() {
        let config = StreamManagerConfig::default();
        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        sm.set_max_streams_uni(1);
        sm.set_max_data(32);
        sm.set_initial_data_limits(0, 0, 20);

        let mut result = [0u8; 32];

        let send_stream = sm.initiate(0x02, None).unwrap();
        sm.append(send_stream, &[4u8; 10], false).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let mut out1 = SmallVec::new();
        let written = sm.emit_single(&mut result[..8], &mut out1).unwrap();

        assert_eq!(result[0], 0x08);
        assert_eq!(result[1] as u64, send_stream);
        assert_eq!(result[2], 4); //DATA BEGIN
        assert_eq!(result[7], 4); //DATA END
        assert_eq!(written, 8);
        assert!(!sm.outbound_ready.is_empty());

        sm.append(send_stream, &[5u8; 10], true).unwrap();

        let mut out2 = SmallVec::new();
        let written2 = sm.emit_single(&mut result[8..], &mut out2).unwrap();

        assert_eq!(result[8], 0x0f);
        assert_eq!(result[9] as u64, send_stream);
        assert_eq!(result[10], 6); //OFF
        assert_eq!(result[11], 14); //LEN
        assert_eq!(result[12], 4); //DATA BEGIN
        assert_eq!(result[25], 5); //DATA END
        assert_eq!(written2, 4 + 14); //HEADER + DATA LEN
        assert!(sm.outbound_ready.is_empty());
        assert_eq!(sm.sent, 20);
    }

    #[test]
    fn stream_manager_ack() {
        let config = StreamManagerConfig::default();
        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        // 1 uni stream with 64 connection limit and 64 initial stream limit
        sm.set_max_streams_uni(1);
        sm.set_max_data(64);
        sm.set_initial_data_limits(0, 0, 64);

        let mut result = [0u8; 64];

        let send_stream = sm.initiate(0x02, None).unwrap();
        sm.append(send_stream, &[4u8; 64], false).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let mut out = SmallVec::new();
        let _ = sm.emit_single(&mut result[..8], &mut out).unwrap();
        let _ = sm.emit_single(&mut result[8..16], &mut out).unwrap();
        let _ = sm.emit_single(&mut result[16..24], &mut out).unwrap();
        let _ = sm.emit_single(&mut result[24..32], &mut out).unwrap();
        let _ = sm.emit_single(&mut result[32..40], &mut out).unwrap();
        let _ = sm.emit_single(&mut result[40..48], &mut out).unwrap();
        let _ = sm.emit_single(&mut result[48..56], &mut out).unwrap();
        let _ = sm.emit_single(&mut result[56..], &mut out).unwrap();

        sm.ack(send_stream, 8, 8);
        sm.ack(send_stream, 16, 8);
        sm.ack(send_stream, 24, 8);

        assert!(!sm
            .outbound
            .get(&send_stream)
            .unwrap()
            .inflight
            .contains_key(&8));
        assert!(!sm
            .outbound
            .get(&send_stream)
            .unwrap()
            .inflight
            .contains_key(&16));
        assert!(!sm
            .outbound
            .get(&send_stream)
            .unwrap()
            .inflight
            .contains_key(&24));
    }

    #[test]
    fn stream_manager_emit_with_prio() {
        let config = StreamManagerConfig::default();
        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        sm.set_max_streams_uni(2);
        sm.set_max_data(32);
        sm.set_initial_data_limits(0, 0, 48);

        let mut result = [0u8; 32];

        let send_stream = sm.initiate(0x02, None).unwrap();
        sm.append(send_stream, &[4u8; 32], false).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let send_stream2 = sm.initiate(0x02, Some(100)).unwrap();
        sm.append(send_stream2, &[5u8; 16], true).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (100, send_stream2));

        let mut out = SmallVec::new();
        let written = sm.emit_single(&mut result, &mut out).unwrap();

        assert_eq!(result[0], 0x0b);
        assert_eq!(result[1] as u64, send_stream2);
        assert_eq!(result[2], 16); //LEN
        assert_eq!(result[3], 5); //DATA BEGIN
        assert_eq!(result[18], 5); //DATA END
        assert_eq!(written, 19);

        let mut out2 = SmallVec::new();
        let written2 = sm.emit_single(&mut result[written..], &mut out2).unwrap();

        assert_eq!(result[19], 0x08);
        assert_eq!(result[20] as u64, send_stream);
        assert_eq!(result[21], 4); //DATA BEGIN
        assert_eq!(result[31], 4); //DATA END
        assert_eq!(written2, 13);
        assert!(!sm.outbound_ready.is_empty());
    }

    #[test]
    fn stream_manager_emit_and_modify_stream_prio() {
        let config = StreamManagerConfig::default();
        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        sm.set_max_streams_uni(3);
        sm.set_max_data(32);
        sm.set_initial_data_limits(0, 0, 64);

        let mut result = [0u8; 32];

        let send_stream = sm.initiate(0x02, None).unwrap();
        sm.append(send_stream, &[4u8; 32], false).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let send_stream2 = sm.initiate(0x02, Some(100)).unwrap();
        sm.append(send_stream2, &[5u8; 16], true).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (100, send_stream2));

        let send_stream3 = sm.initiate(0x02, Some(10)).unwrap();
        sm.append(send_stream3, &[6u8; 16], true).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (10, send_stream3));

        let mut out = SmallVec::new();
        let written = sm.emit_single(&mut result, &mut out).unwrap();

        assert_eq!(result[0], 0x0b);
        assert_eq!(result[1] as u64, send_stream3);
        assert_eq!(result[2], 16); //LEN
        assert_eq!(result[3], 6); //DATA BEGIN
        assert_eq!(result[18], 6); //DATA END
        assert_eq!(written, 19);

        let mut out2 = SmallVec::new();
        sm.set_priority(send_stream, 5).unwrap();
        let written2 = sm.emit_single(&mut result[written..], &mut out2).unwrap();

        assert_eq!(result[19], 0x08);
        assert_eq!(result[20] as u64, send_stream);
        assert_eq!(result[21], 4); //DATA BEGIN
        assert_eq!(result[31], 4); //DATA END
        assert_eq!(written2, 13);
        assert!(!sm.outbound_ready.is_empty());
    }

    #[test]
    fn stream_manager_emit_fill() {
        let config = StreamManagerConfig::default();
        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        sm.set_max_data(48);
        sm.set_max_streams_uni(3);
        sm.set_initial_data_limits(0, 0, 64);

        let mut result = [0u8; 48];

        let send_stream = sm.initiate(0x02, None).unwrap();
        sm.append(send_stream, &[4u8; 16], false).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let send_stream2 = sm.initiate(0x02, None).unwrap();
        sm.append(send_stream2, &[5u8; 16], true).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let send_stream3 = sm.initiate(0x02, None).unwrap();
        sm.append(send_stream3, &[6u8; 32], true).unwrap();

        assert_eq!(*sm.outbound_ready.first().unwrap(), (u8::MAX, send_stream));

        let mut out = SmallVec::new();
        let written = sm.emit_fill(&mut result, &mut out).unwrap();

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
    fn stream_manager_upgrade_max_data() {
        let config = StreamManagerConfig {
            initial_max_data: 1024,
            initial_max_bidi_streams: 1,
            initial_inbound_limits: fc::InitialStreamDataLimits {
                max_stream_data_bidi_remote: 1024,
                ..InitialStreamDataLimits::default()
            },
            ..StreamManagerConfig::default()
        };

        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        let bidi1 = 0x00;
        sm.incoming(bidi1, 0, 800, true, &[1u8; 800]).unwrap();

        assert_eq!(sm.flow_control.len(), 800);

        let n_md = sm.upgrade_max_data();

        assert_eq!(n_md, 1024 + 2048);
    }

    #[test]
    fn stream_manager_upgrade_max_stream_data() {
        let config = StreamManagerConfig {
            initial_max_data: 1024,
            initial_max_bidi_streams: 2,
            initial_max_uni_streams: 2,
            initial_inbound_limits: fc::InitialStreamDataLimits {
                max_stream_data_bidi_remote: 1024,
                ..InitialStreamDataLimits::default()
            },
            max_send_buffer: 1024,
        };

        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        let bidi1 = 0x00;
        sm.incoming(bidi1, 0, 800, true, &[1u8; 800]).unwrap();

        let mut buf_r = [0u8; 10];
        let mut buf = octets::OctetsMut::with_slice(&mut buf_r);

        assert_eq!(*sm.pending_max_stream_data.front().unwrap(), bidi1);

        sm.upgrade_max_stream_data(&mut buf).unwrap();

        assert_eq!(buf_r[0], 0x11);
        assert_eq!(buf_r[1] as u64, bidi1);
        assert_eq!(buf_r[2], 0x4c); // varint 3072
        assert_eq!(buf_r[3], 0x00);

        assert!(sm.pending_max_stream_data.is_empty());
    }

    #[test]
    fn stream_manager_upgrade_peer_stream_limits() {
        let config = StreamManagerConfig {
            initial_max_data: 1024,
            initial_max_bidi_streams: 2,
            initial_max_uni_streams: 2,
            initial_inbound_limits: fc::InitialStreamDataLimits {
                max_stream_data_bidi_remote: 1024,
                ..InitialStreamDataLimits::default()
            },
            max_send_buffer: 1024,
        };

        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);

        let bidi1 = 0x00;
        sm.incoming(bidi1, 0, 800, true, &[1u8; 800]).unwrap();

        let mut buf_r = [0u8; 10];
        let mut buf = octets::OctetsMut::with_slice(&mut buf_r);

        sm.upgrade_peer_stream_limits(&mut buf).unwrap();

        assert_eq!(buf_r[0], 0x12);
        assert_eq!(buf_r[1], 0x07);
        assert_eq!(buf_r[2], 0x00);

        assert_eq!(sm.limits[(sm.local ^ 0x01) as usize], 0x07);
    }

    #[test]
    fn stream_manager_stream_data_limits_as_server() {
        let config = StreamManagerConfig {
            initial_max_data: 1024,
            initial_max_bidi_streams: 2,
            initial_max_uni_streams: 2,
            initial_inbound_limits: fc::InitialStreamDataLimits {
                max_stream_data_bidi_remote: 1024,
                max_stream_data_bidi_local: 256,
                max_stream_data_uni: 512,
            },
            max_send_buffer: 1024,
        };

        let mut sm = StreamManager::new(config, rustls::Side::Server as u8);
        sm.set_initial_data_limits(300, 310, 320);
        sm.set_max_streams_bidi(1);

        // incoming bidi stream
        let r_bidi = 0x00;
        sm.incoming(r_bidi, 0, 128, true, &[1u8; 128]).unwrap();

        let ss_r_bidi = sm.outbound.get(&r_bidi).unwrap();
        let rs_r_bidi = sm.inbound.get(&r_bidi).unwrap();

        assert_eq!(ss_r_bidi.max_data, 300);
        assert_eq!(rs_r_bidi.flow_control.max_data(), 1024);

        // outgoing bidi stream
        let s_bidi = sm.initiate(0x00, None).unwrap();

        let ss_s_bidi = sm.outbound.get(&s_bidi).unwrap();
        let rs_s_bidi = sm.inbound.get(&s_bidi).unwrap();

        assert_eq!(ss_s_bidi.max_data, 310);
        assert_eq!(rs_s_bidi.flow_control.max_data(), 256);
    }

    #[test]
    fn stream_manager_stream_data_limits_as_client() {
        let config = StreamManagerConfig {
            initial_max_data: 1024,
            initial_max_bidi_streams: 2,
            initial_max_uni_streams: 2,
            initial_inbound_limits: fc::InitialStreamDataLimits {
                max_stream_data_bidi_remote: 1024,
                max_stream_data_bidi_local: 256,
                max_stream_data_uni: 512,
            },
            max_send_buffer: 1024,
        };

        let mut sm = StreamManager::new(config, rustls::Side::Client as u8);
        sm.set_initial_data_limits(300, 310, 320);
        sm.set_max_streams_bidi(1);

        // incoming bidi stream
        let r_bidi = 0x01;
        sm.incoming(r_bidi, 0, 128, true, &[1u8; 128]).unwrap();

        let ss_r_bidi = sm.outbound.get(&r_bidi).unwrap();
        let rs_r_bidi = sm.inbound.get(&r_bidi).unwrap();

        assert_eq!(ss_r_bidi.max_data, 300);
        assert_eq!(rs_r_bidi.flow_control.max_data(), 1024);

        // outgoing bidi stream
        let s_bidi = sm.initiate(0x00, None).unwrap();

        let ss_s_bidi = sm.outbound.get(&s_bidi).unwrap();
        let rs_s_bidi = sm.inbound.get(&s_bidi).unwrap();

        assert_eq!(ss_s_bidi.max_data, 310);
        assert_eq!(rs_s_bidi.flow_control.max_data(), 256);
    }

    #[test]
    fn recv_stream_upgrade_max_stream_data() {
        let data = vec![1u8; 800];

        let mut recv_stream = RecvStreamInner::with_data(&data, 0, false);

        let n_msd = recv_stream.upgrade_max_data();

        assert_eq!(n_msd, 1024 + 2048);
    }

    #[test]
    fn recv_stream_creation() {
        let data = vec![1u8; 8];

        let recv_stream = RecvStreamInner::with_data(&data, 0, true);

        assert_eq!(recv_stream.flow_control.len(), 8);
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
        assert_eq!(recv_stream.flow_control.len(), 24);
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
        assert_eq!(recv_stream.flow_control.len(), 40);
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
    fn recv_stream_read_twice() {
        let frame1 = vec![1u8; 8];
        let frame2 = vec![2u8; 8];

        let mut recv_stream = RecvStreamInner::with_data(&frame1, 0, false);
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
    fn send_stream_emit_split_and_retain() {
        let mut ss = SendStreamInner::new(None, 1024, 1024);
        ss.append(b"ABCDEFGHIJ", true).unwrap();

        let mut p1 = [0u8; 4];
        assert_eq!(ss.emit(&mut p1).unwrap(), (0, 4, false));
        assert_eq!(&p1[..], b"ABCD");

        let mut p2 = [0u8; 6];
        assert_eq!(ss.emit(&mut p2).unwrap(), (4, 6, true));
        assert_eq!(&p2[..], b"EFGHIJ");

        ss = SendStreamInner::new(None, 1024, 1024);
        ss.append(b"AAAA", false).unwrap();
        ss.append(b"BBBB", false).unwrap();
        ss.append(b"CCCC", true).unwrap();

        let mut p = [0u8; 12];
        assert_eq!(ss.emit(&mut p).unwrap(), (0, 12, true));
        assert_eq!(&p[..], b"AAAABBBBCCCC");

        let retained: usize = ss.inflight.iter().map(|(_, chunk)| chunk.len()).sum();
        assert_eq!(retained, 12);
    }

    #[test]
    fn send_stream_emit_lost_packets_are_requeued_correctly() {
        let mut ss = SendStreamInner::new(None, 1024, 1024);
        ss.append(b"AAAABBBBCCCC", false).unwrap();

        // two packets, 4 bytes each
        let mut p1 = [0u8; 4];
        ss.emit(&mut p1).unwrap();
        let mut p2 = [0u8; 4];
        ss.emit(&mut p2).unwrap();
        let mut p3 = [0u8; 4];
        ss.emit(&mut p3).unwrap();
        assert_eq!(ss.off, 12);
        assert!(!ss.readable());

        // the app writes more while those are in flight
        ss.append(b"DDDD", true).unwrap();

        // both packets are declared lost, out of order
        ss.lost(0, 4);
        ss.lost(4, 4);
        ss.lost(8, 4);

        // the queue must be [0..4][4..8][8..12][12..16], lowest offset first
        let offs: Vec<u64> = ss.data.iter().map(|c| c.off()).collect();
        assert_eq!(offs, vec![0, 4, 8, 12]);

        // a retransmit does not change the order
        let before = ss.off;
        let mut p3 = [0u8; 16];
        let (_, len, fin) = ss.emit(&mut p3).unwrap();

        assert_eq!(len, 16);
        assert!(fin);
        assert_eq!(&p3[..], b"AAAABBBBCCCCDDDD");
        assert_eq!(ss.off, 16);
        assert!(ss.off >= before);
    }

    #[test]
    fn send_stream_emit_a_gap_ends_the_frame() {
        let mut ss = SendStreamInner::new(None, 1024, 1024);
        ss.append(b"AAAA", false).unwrap(); // 0..4
        ss.append(b"BBBB", false).unwrap(); // 4..8

        // two separate packets so losing one leaves the other in flight
        let mut p1 = [0u8; 4];
        ss.emit(&mut p1).unwrap();
        let mut p2 = [0u8; 4];
        ss.emit(&mut p2).unwrap();

        ss.append(b"CCCC", false).unwrap(); // 8..12, queued behind
        ss.lost(0, 4); // 4..8 is still in flight

        // queue is now [0..4][8..12], a gap at 4..8 which is still in flight
        let offs: Vec<u64> = ss.data.iter().map(|c| c.off()).collect();
        assert_eq!(offs, vec![0, 8]);

        // peek must stop at the discontinuity, not merge across it
        assert_eq!(ss.peek(), Some((0, 4)));

        // emit must not concatenate 0..4 and 8..12 into one frame
        let mut f = [0u8; 8];
        let (_, len, _) = ss.emit(&mut f).unwrap();
        assert_eq!(len, 4);
        assert_eq!(&f[..4], b"AAAA");

        // the next frame starts at the far side of the gap
        assert_eq!(ss.peek(), Some((8, 4)));

        assert_eq!(ss.off, 8);
        ss.lost(0, 4); // 0..4 comes back again

        let mut r = [0u8; 8];
        let (_, len, _) = ss.emit(&mut r).unwrap();

        assert_eq!(len, 4);
        assert_eq!(&r[..4], b"AAAA");
    }

    #[test]
    fn send_stream_reset() {
        let frame1 = vec![1u8; 8];
        let mut result = vec![0u8; 8];

        let mut send_stream = SendStreamInner::new(None, 8, 1024);

        send_stream.append(&frame1, false).unwrap();

        send_stream.reset(0xf).unwrap();

        assert!(send_stream.inflight.is_empty());

        //assert appending and emitting is disabled after reset
        assert!(send_stream.append(&frame1, true).is_err());
        assert!(send_stream.emit(&mut result).is_none());
    }

    #[test]
    fn send_stream_readable() {
        let frame1 = vec![1u8; 8];
        let mut result = vec![0u8; 8];

        let mut send_stream = SendStreamInner::new(None, 8, 1024);

        assert!(!send_stream.readable());

        send_stream.append(&frame1, true).unwrap();

        assert!(send_stream.readable());

        send_stream.emit(&mut result).unwrap();

        assert!(!send_stream.readable());
    }

    fn emit_one(send: &mut CryptoSend, cap: usize) -> Option<(u64, Vec<u8>)> {
        let mut back = vec![0u8; cap];
        let mut buf = octets::OctetsMut::with_slice(&mut back);
        let r = send.emit(&mut buf).unwrap();
        let n = buf.off();
        r.map(|(off, _)| (off, back[..n].to_vec()))
    }

    fn pending_offs(send: &CryptoSend) -> Vec<u64> {
        send.pending.iter().map(|c| c.off()).collect()
    }

    #[test]
    fn crypto_send_append() {
        let mut s = CryptoSend::default();
        s.append(&[1, 2, 3]);
        s.append(&[]);
        s.append(&[4, 5]);
        assert_eq!(s.len, 5);
        assert_eq!(s.pending.len(), 2);
        assert!(s.wants_write());
        assert_eq!(s.contiguous_data(), (0, 5));
    }

    #[test]
    fn crypto_send_emit() {
        let mut s = CryptoSend::default();
        s.append(&[0xAA, 0xBB, 0xCC]);
        let (off, frame) = emit_one(&mut s, 64).unwrap();
        assert_eq!(off, 0);
        assert_eq!(frame[0], 0x06);
        assert_eq!(frame[1], 0);
        assert_eq!(frame[2], 3);
        assert_eq!(&frame[3..], &[0xAA, 0xBB, 0xCC]);
        assert!(!s.wants_write());
        assert_eq!(s.inflight.len(), 1);

        let mut s = CryptoSend::default();
        s.append(&[1, 2, 3]);
        assert!(emit_one(&mut s, 3).is_none());
        assert!(s.wants_write());
        assert!(s.inflight.is_empty());

        let mut s = CryptoSend::default();
        s.append(&(0..10u8).collect::<Vec<_>>());
        let (o1, _) = emit_one(&mut s, 3 + 4).unwrap();
        let (o2, _) = emit_one(&mut s, 64).unwrap();
        assert_eq!((o1, o2), (0, 4));
        assert!(!s.wants_write());
        assert_eq!(s.inflight.len(), 2);
    }

    #[test]
    fn crypto_send_ack() {
        let mut s = CryptoSend::default();
        s.append(&(0..12u8).collect::<Vec<_>>());
        emit_one(&mut s, 3 + 4).unwrap();
        emit_one(&mut s, 3 + 4).unwrap();
        emit_one(&mut s, 64).unwrap();
        assert_eq!(s.inflight.len(), 3);

        s.ack(4, 4);
        let mut offs: Vec<u64> = s.inflight.iter().map(|c| c.off()).collect();
        offs.sort_unstable();
        assert_eq!(offs, vec![0, 8]);

        s.ack(0, 4);
        s.ack(8, 4);
        assert!(s.inflight.is_empty());
    }

    #[test]
    fn crypto_send_lost() {
        let mut s = CryptoSend::default();
        s.append(&(0..10u8).collect::<Vec<_>>());
        emit_one(&mut s, 3 + 4).unwrap();
        emit_one(&mut s, 64).unwrap();
        s.ack(4, 6);
        s.lost(0, 4);
        assert!(s.inflight.is_empty());
        assert_eq!(emit_one(&mut s, 64).unwrap().0, 0);

        let mut s = CryptoSend::default();
        s.append(&(0..12u8).collect::<Vec<_>>());
        emit_one(&mut s, 3 + 4).unwrap();
        emit_one(&mut s, 3 + 4).unwrap();
        emit_one(&mut s, 64).unwrap();
        s.ack(4, 4);
        s.lost(8, 4);
        s.lost(0, 4);
        assert_eq!(pending_offs(&s), vec![0, 8]);
        assert_eq!(s.contiguous_data(), (0, 4));
        assert_eq!(emit_one(&mut s, 64).unwrap().0, 0);
        assert_eq!(emit_one(&mut s, 64).unwrap().0, 8);
        assert!(!s.wants_write());
    }

    #[test]
    fn crypto_send_clear() {
        let mut s = CryptoSend::default();
        s.append(&[1, 2, 3, 4]);
        emit_one(&mut s, 3 + 2).unwrap();
        assert!(!s.inflight.is_empty() && !s.pending.is_empty());
        s.clear();
        assert!(s.inflight.is_empty());
        assert!(!s.wants_write());
    }

    #[test]
    fn crypto_recv() {
        let mut r = CryptoRecv::default();
        let mut got = Vec::new();
        r.recv(0, &[1, 2, 3], |b| {
            got.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        r.recv(3, &[4, 5], |b| {
            got.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        assert_eq!(got, vec![1, 2, 3, 4, 5]);
        assert_eq!(r.next, 5);
        assert!(r.buffered.is_empty());

        let mut r = CryptoRecv::default();
        let mut got = Vec::new();
        r.recv(3, &[4, 5, 6], |b| {
            got.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        assert!(got.is_empty());
        assert_eq!(r.buffered_bytes, 3);
        r.recv(0, &[1, 2, 3], |b| {
            got.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        assert_eq!(got, vec![1, 2, 3, 4, 5, 6]);
        assert_eq!(r.next, 6);
        assert!(r.buffered.is_empty() && r.buffered_bytes == 0);

        let mut r = CryptoRecv::default();
        let mut got = Vec::new();
        r.recv(0, &[1, 2, 3, 4], |b| {
            got.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        got.clear();
        r.recv(0, &[1, 2, 3, 4], |b| {
            got.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        r.recv(1, &[2, 3], |b| {
            got.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        assert!(got.is_empty());
        r.recv(2, &[3, 4, 5, 6], |b| {
            got.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        assert_eq!(got, vec![5, 6]);
        assert_eq!(r.next, 6);

        let mut r = CryptoRecv::default();
        let mut got = Vec::new();
        r.recv(9, &[9], |b| {
            got.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        r.recv(3, &[3], |b| {
            got.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        r.recv(3, &[3], |b| {
            got.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        r.recv(6, &[6], |b| {
            got.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            r.buffered.iter().map(|c| c.off()).collect::<Vec<_>>(),
            vec![3, 6, 9]
        );
        let mut r = CryptoRecv::default();
        let mut got = Vec::new();
        r.recv(10, &[10, 11, 12, 13, 14], |b| {
            got.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        r.recv(13, &[13, 14, 15, 16], |b| {
            got.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        r.recv(0, &[0u8; 10], |b| {
            got.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        assert_eq!(r.next, 17);

        let mut r = CryptoRecv::default();
        let big = vec![0u8; CRYPTO_RECV_BUFFER_LIMIT + 1];
        let err = r.recv(1, &big, |_| Ok(())).unwrap_err();
        assert_eq!(
            err.kind(),
            terror::QuicTransportError::CryptoBufferExceeded as u64
        );
        assert!(r.buffered.is_empty());

        let mut r = CryptoRecv::default();
        assert!(r
            .recv(0, &[1, 2], |_| Err(terror::Error::quic_transport_error(
                "boom",
                terror::QuicTransportError::ProtocolViolation
            )))
            .is_err());
    }
}
