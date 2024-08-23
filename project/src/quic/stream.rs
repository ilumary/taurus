use crate::{terror, Inner};

use std::{collections::VecDeque, sync::Arc};

use indexmap::IndexMap;

const STREAM_TYPE: u64 = 0x3;
const CLIENT_INIT_BIDI: u64 = 0x00;
const SERVER_INIT_BIDI: u64 = 0x01;
const CLIENT_INIT_UNI: u64 = 0x02;
const SERVER_INIT_UNI: u64 = 0x03;

// stores and manages streams for connection
pub struct StreamManager {
    streams: IndexMap<StreamId, Stream>,
}

impl StreamManager {
    pub fn new() -> Self {
        Self {
            streams: IndexMap::<StreamId, Stream>::new(),
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
        if let Some(s) = self.streams.get(&StreamId(stream_id)) {
            s.incoming();
        }
        Ok(())
    }

    pub fn _initiate(&mut self, s_type: u64, data: Vec<u8>) {}
}

pub struct Stream {
    id: StreamId,

    // existence of outbound/inbound data determines if stream is uni/bidirectional
    outbound: Option<SendStream>,
    inbound: Option<RecvStream>,
}

impl Stream {
    fn new(id: u64) -> Self {
        Self {
            id: StreamId(id),
            outbound: None,
            inbound: None,
        }
    }

    fn incoming(&self) {}
}

#[derive(Eq, PartialEq, Hash)]
struct StreamId(u64);

struct SendStream {
    state: SendStreamState,

    //data chunks ordered in outgoing direction
    data: VecDeque<Chunk>,
}

enum SendStreamState {
    Ready,
    Send,
    DataSent,
    ResetSent,
    DataRecvd,
    ResetRecvd,
}

struct RecvStream {
    state: RecvStreamState,

    //data chunks ordered by their offset
    data: IndexMap<u64, Chunk>,
}

enum RecvStreamState {
    Recv,
    SizeKnown,
    DataRecvd,
    ResetRecvd,
    DataRead,
    ResetRead,
}

//single chunk of data
struct Chunk {
    data: Arc<Vec<u8>>,

    off: u64,

    pos: u64,

    len: u64,

    fin: bool,
}
