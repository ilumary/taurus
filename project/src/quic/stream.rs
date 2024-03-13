use std::{collections::BTreeMap, sync::Arc};

// stores and manages streams for connection
struct StreamManager {}

struct Stream {
    id: usize,

    // existence of outbound/inbound data determines if stream is uni/bidirectional
    outbound: Option<SendStream>,
    inbound: Option<RecvStream>,
}

struct SendStream {
    //send state

    //vec dequeue
}

struct RecvStream {
    //recv state

    //BTreeMap
}

//single chunk of data
struct Chunk {
    data: Arc<Vec<u8>>,

    off: u64,

    pos: u64,

    len: u64,

    fin: bool,
}
