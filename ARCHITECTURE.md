# Taurus Architecture

Taurus is a currently under development QUIC library written in Rust. It is mainly a hobby and research project which I grew out of my bachelor thesis out of pure interest. Certain decisions regarding the architecture may be overhauled at any point as my learning progresses. The API should not be relied upon as stable. This project may never leave the experimental stage. This document will try and explain some of my thoughts and techniques that I used. This document also requires some knowledge of the QUIC state machine and some of its internals, if you want to get started on that first have a look at my bachelor thesis.

## General Design

Taurus is comprised of two main parts:
1. the core library in lib.rs
2. the io layer thats built ontop of the core library

## Core Library

The core library comprises a single main struct `Inner` which includes the complete QUIC state machine including tls13 session management, per-path congestion control including loss detection and retransmissions, stream managment, flow control, error handling, packet parsing, packet generation, connection id management, and much more. Each of those is contained within a rust module and designed to be as capsuled as possible so that I can test each module on its own as best as possible.

`Inner` provides a public API that's designed to be as simple as possible. The four main entry points are `accept()`, `connect()`, `recv()`, and `fetch_dgram()`. As you can probably guess, `accept()` and `connect()` are the two constructors for the server and client case, respectively. `recv()` is called for every received packet for that connection, and `fetch_dgram()` is called to emit a packet into a provided buffer. `Inner` does not manage any packet buffers directly. It works purely on mutable slices and encrypts/decrypts/encodes/decodes in place.

In addition to these function there are a number of other functions to manage streams, get timers, handle timouts and so on.

I opted for an event based design instead of a polling one as the nature of network communication is neither deterministic nor constant.

### Events

Nearly every action on the core library can generate an event. These can be queried with `Inner::poll_events()`. Currently there are these events:

| Event | Payload | Meaning |
|---|---|---|
| `ConnectionEstablished` | — | Emitted once per connection, when it becomes established and available to the application. |
| `NewConnectionId` | `cid::Id` | Emitted when our side issues a new connection ID to the peer, so the I/O layer knows which connection IDs map to which connection. |
| `RetireConnectionId` | `cid::Id` | Emitted when we receive a `RETIRE_CONNECTION_ID` from the peer, indicating it will no longer use that ID to address our endpoint. |
| `ClosedByPeer` | — | Emitted when the connection has been closed by the peer. |
| `StreamOpenable` | `bool` | Emitted by the stream manager when a new stream can be opened after an earlier open attempt was blocked by the peer's flow-control limits. `true` = bidirectional, `false` = unidirectional. |
| `StreamAcceptable` | `bool` | Emitted by the stream manager when a new stream can be accepted after an earlier accept attempt found no stream available. `true` = bidirectional, `false` = unidirectional. |
| `StreamReadable` | `u64` (stream id) | Emitted by the stream manager when a stream has new data to read after an earlier read found none available. Carries the stream ID. |
| `StreamWritable` | `u64` (stream id) | Emitted by the stream manager when a send stream can send data again after an earlier write was blocked by local buffer limits. Carries the stream ID. |
| `StreamFinished` | `u64` (stream id) | Emitted by the stream manager when a stream is finished: the FIN bit has been set and all data has been sent and acknowledged. Carries the stream ID. |

The stream events in particular are reactive, meaning if we query something and it is available it is returned immediately. If it is not we remember that and once it becomes available we emit an event. That way we can register a task waker in the outer io layer for example that mirrors the inner state without having to worry about anything external in the internal stream manager.

### Streams

QUIC streams are the integral part of the protocol. I implemented a `StreamManager`, a `SendStreamInner`, and a `RecvStreamInner`. Via the API of the stream manager one can open a stream, handle any incoming stream packet, emit data from any ready stream, and handle the various flow control limits for streams and data. Again, its designed to be standalone and is extensively tested.

Additionally I added specialised versions of the send and recv streams for crypto data, `CryptoSend` and `CryptoRecv`. They do not have flow control limits and lack some integral parts of the normal streams which makes them a lot smaller and easier to implement.

All streams handle the underlying data via a `Chunk`. The idea is to minimize copying while providing managed access for as long as the data is not consumed. A `Chunk` stores its data in an `Arc<[u8]>`. Data that has to be sent, or that arrived in a packet, is copied once into a `Chunk`. Alongside the data, a `Chunk` tracks start, offset, position, and length fields relative to its internal buffer, so it can be copied trivially and address different portions of the same allocation as efficiently as possible. The reference count in the `Arc<[u8]>` keeps the data alive while any number of Chunks hold it. This solves tracking data for congestion control and possible retransmission without copying: once the data is either fully consumed by the application or written on the wire and acknowledged, all chunks are dropped and the underlying allocation with them, so data is kept only as long as it has to be.

The total amount of unacknowledged data a send stream will buffer is bounded by the stream's send buffer. Sending large amounts of data is best done in smaller appends so the memory footprint of local tracking stays small, otherwise the whole payload has to stay resident until its last byte is acknowledged.

### Congestion Control

The congestion control module sits behind any path on which data is sent. It tracks round-trip-times, sent bytes, sent frames and handles losses in case of a timeout or a non-acked packet.

Most of the congestion control module is somewhat standard. Each path can set its own congestion detection algorithm. A user may want to implement its own algorithm and can do so via the trait `CongestionAlgorithm`. At the time of writing this, some of the nuances are still work in progress.

#### Sent Packet Tracking

To correctly implement congestion control I require a mechanism to track sent packets. My initial idea was to use a `VecDeque<SentPacket>`. Extensive benchmarking then indicated that this is indeed the fastest solution for tracking a few hundred packets. If the tracked packets went above 1000, it was notably faster to use a `BTreeMap<u64, (usize, SmallVec<[SentPacket; 256]>)>`, which is a chunked list essentially. Cache locality on larger packet numbers was great but with lower packet numbers it was notably slower than the `VecDeque<SentPacket>`. After tinkering around for a few days I found the reason: for higher packet numbers and randomized input for removing ranges, the `VecDeque<SentPacket>` has to shift for every removal thats not optimal, i.e. taking from the end. This means a lot of copying which is slow. Seems logical in hindsight but I was genuinely scratching my head. To solve this I added a "tombstone", so a placeholder that prevents shifting: `VecDeque<Option<SentPacket>>`. Now I just remove from the beginning and append to the end, both of which should just reduce to pointer shifting and the occasional allocation in the beginning (which can also be reduced by just reserving space). This way, removal of a range, even for thousands of active packets, stays in the nanosecond area.

#### Sent Frame Tracking

Each `SentPacket` will have content associated with it which, in the case of a loss event, needs to be resent. Obviously I cannot copy the whole packet. Also just copying each frame is also extremely inefficient as it basically requires us to keep the data in two places at once or move it. To circumvent this I added a custom enum `SentFrame` which only tracks the Frames it needs to and only with the minimum required amount of information. An example for a frame that does not need to be tracked is the STREAMS_BLOCKED frame as its implicit on earlier frames which means if I send it again with the same or a bigger value it implicates all earlier frames. An example for a frame that needs tracking is the STREAM frame which carries stream data. To do that efficiently the `Stream` variant of the `SentFrame` enum only carries the stream id, the offset of the data within, the length of the data and if the fin bit it set. Combined with the `SendStreamInner` tracking sent Chunks keyed by offset one can very easily retrieve the exact data chunk that was lost and resend it while only remembering a handful of bytes. Same for a NEW_CONNECTION_ID frame as another example. The connection id itself is saved in my ConnectionIdManager. When a new connection id is issued it gets a sequence number which is essentially just an increasing counter and an index into an array. The `NewCid` variant of the `SentFrame` enum only tracks that sequence number. Again, in case a packet containing such a frame is lost, the only thing thats tracked is a single `u64`.

## IO Layer

The io layer is designed ontop of my core QUIC library. It comprises a thread-local executor with a sharded endpoint design and a threadpool for offloading intensive workloads.

Throughout the last few years I have gone through a few designs for such a QUIC endpoint. Initially I used a normal, synchronous loop without many features. As I expanded the functionality the expectations on my io layer also grew. Eventually I landed on tokio and a fully asynchronous endpoint design where each task is managed by tokio. While extensively testing that design I noticed a flaw in the scaling: at high core counts the continuous switching between cores cause the caches to be extremely volatile as every packet could be processed on a different core and the whole connection state needed to be pulled between cores. So I decided to redesign the endpoint and reduce complexity.

The design I came up with keeps connections on the same core while providing its own asynchronous runtime so that the API can stay nice. Essentially each core runs on an event loop which waits on either a new packet or a registered deadline. This wait is blocking. If the socket is readable, the packet is retrieved and processed. If a timer fired the respective timeout is processed. Then the thread local executor runs the user tasks, possible connect request are handled and then all ready connection drain their ready packets which are then sent. A watchdog notes runtime of the turn to protect from overrunning user tasks and the loop starts again.

The thread local design has many advantages. There is no need for synchronisation primitives, packets and connections are always kept on the same thread and can populate the cache, and the io handling gets a lot simpler.

### Offload Pool

The thread-local design has one issue: because a shard runs protocol work and user tasks on the same thread, anything thats CPU intensive or blocking in a handler stalls every connection on that core. The offload pool exists to move that work off the shard. It is a small multi-threaded Tokio runtime (wip on making that runtime interchangeable) shared across the endpoint, exposed through `conn.offload(fut)` for Send futures and `conn.offload_blocking(f)` for blocking closures. Both hand the work to the pool and await the result back on the owning shard, so the connection state never leaves its core.

By default the pool runs one thread per shard. The count is configurable for workloads that lean more or less heavily on offloaded work. Its threads are pinned to the cores the shards don't occupy where such cores exist, and left unpinned otherwise, so offload work and the latency-sensitive shard loop stay off each other's cores.

### IO Layer Backend

The packet sending and receiving is backed by two custom backends. One is based on polling and the other one is based on linux's io_uring. The latter is obviously only available on linux and since kernel version 6.0. As of writing this my io_uring backend is still under active development.

The first backend is (p)poll based and has paths for both linux and macos. Both paths feature fast network io feature support. For macos the private batched messaging api `recvmsg_x` and `sendmsg_x` is used. For linux the `recvmmsg` and `sendmmsg` batch calls are used. As a secondary feature the linux polling backend also supports gso and gro. 

The second backend is the linux io_uring backend. It is gated behind the `uring_backend` feature as io_uring had its fair share of vulnerabilities in the past and may not be preferred by some. io_uring uses two ring buffers, the submission queue and the completion queue, which are shared between user and kernel space. Batching happens implicitly by enqueuing multiple send requests which can be submitted with a single call. Additionally the backend also supports gso and gro enabling packet slicing in the kernel.

### Sharding and Routing

An endpoint runs one shard per worker, each pinned to its own core with its own socket bound via SO_REUSEPORT, so the kernel load-balances inbound datagrams across shards by 4-tuple hash. Each shard owns a disjoint set of connections, which is what lets the whole design avoid synchronisation primitives on the hot path.

Because the linux kernel hashes on the 4-tuple, a datagram can land on the wrong shard when a peer migrates to a new address. I am still working on a solution to determine the right shard for such a packet. Once I implemented that it will be forwarded to the right shard.

Servers run as many shards as configured workers. A client is clamped to a single shard: it drives its own outbound connections and its root future only ever runs on shard 0. On macOS, SO_REUSEPORT does not load-balance (it delivers to the most recently bound socket), so shard count is clamped to one regardless.