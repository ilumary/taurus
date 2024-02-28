use std::{collections::BTreeMap, sync::Arc};

// stores and manages streams for connection
struct StreamManager {}

// Represents a Quic Stream as per rfc 9000 section 2
// Referenced by a unique streamId with u64 type
struct QuicStream {
    // byte buffer for receiving
    recv_buffer: ChunkedByteBuffer,
    // byte buffer for sending
    send_buffer: ChunkedByteBuffer,
    // if stream is unidirectional
    unidirectional: bool,
    // if stream is bidirectional
    bidirectional: bool,
    // if stream was created on the local endpoint
    local: bool,
    // if stream was created on the remote endpoint
    remote: bool,
    // stream priority [0..128], lower is better
    prio: u8,
}

struct ChunkedByteBuffer {
    data: BTreeMap<u64, Chunk>,

    // total data length
    len: u64,

    // current data chunk, identified by offset, while reading or writing
    off: u64,

    // offset of data chunk with last byte
    fin: Option<u64>,
}

//single chunk of data
struct Chunk {
    data: Arc<Vec<u8>>,

    off: u64,

    pos: u64,

    len: u64,

    fin: bool,
}
