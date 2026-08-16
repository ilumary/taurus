use std::{
    cell::RefCell,
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, VecDeque},
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::{Duration, Instant},
};

use async_task::Task;
use crossbeam_channel::{Receiver, Sender};
use slab::Slab;
use tokio::sync::oneshot;
use tracing::Instrument;

use crate::{
    cid,
    connection::{Client, ConnState, Connection},
    executor::{self, LocalExec, Offload, Watchdog},
    io::{buffer::RecvBuf, BatchConfig, CrossThreadWaker, Io},
    packet::Header,
    Inner, InnerEvent,
};

/// length for local ids
pub const LOCAL_CID_LEN: usize = 8;

/// the application handler, cloned into every shard and invoked on the shard that
/// owns the connection. the future it builds is `!Send` and never leaves that core
pub(crate) type Handler =
    Arc<dyn Fn(Connection) -> Pin<Box<dyn Future<Output = ()>>> + Send + Sync>;

/// a client's root future, handed to shard 0 and built there
pub(crate) type RootFn = Box<dyn FnOnce(Client) -> Pin<Box<dyn Future<Output = ()>>> + Send>;

/// endpoint wide configuration
#[derive(Debug, Clone)]
pub struct EndpointConfig {
    /// shards, each pinned to its own core. clamped to 1 on darwin, where
    /// SO_REUSEPORT does not load balance
    pub workers: usize,

    /// pin each shard to a core, linux only
    pub pin_cores: bool,

    /// GSO segment size, also the size of a single datagram. no accessor exists on
    /// Inner, so the path MTU comes from here
    pub mtu: usize,

    /// datagrams a single connection may serialise in one egress pass
    pub tx_burst: usize,

    /// tasks run per loop turn, bounds how long app code can delay the socket
    pub task_budget: usize,

    /// a turn longer than this means a handler is blocking the shard
    pub turn_warn: Duration,

    /// tokio threads for `conn.offload`. 0 defaults to one thread per shard
    pub offload_threads: usize,

    /// buffer pool and offload knobs for the io backend
    pub io: BatchConfig,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            workers: 1,
            pin_cores: true,
            mtu: 1200,
            tx_burst: 64,
            task_budget: executor::TASK_BUDGET,
            turn_warn: Duration::from_millis(5),
            offload_threads: 0,
            io: BatchConfig::default(),
        }
    }
}

/// cross-shard communication
#[derive(Clone)]
pub struct Mailbox {
    tx: Sender<ShardMsg>,

    /// cross thread waker
    waker: CrossThreadWaker,

    /// set to true while the owning shard is blocked in Io::poll
    parked: Arc<AtomicBool>,
}

impl Mailbox {
    #[inline]
    pub fn send(&self, msg: ShardMsg) {
        if self.tx.send(msg).is_err() {
            return;
        }

        if self.parked.swap(false, Ordering::SeqCst) {
            self.waker.wake();
        }
    }
}

/// datagrams that arrive at the wrong shard must be forwarded. happens rarely in practice
/// only when peer changes its origin. if that happens a new cid is issues, directing
/// packets to the right shard automatically again
pub struct ForwardedDatagram {
    data: Box<[u8]>,
    src: SocketAddr,
    ecn: u8,
}

/// shard control message. connection wakes and connects are shard-local now, so
/// only genuinely cross-thread traffic travels here
pub enum ShardMsg {
    Forwarded(ForwardedDatagram),
    Shutdown,
}

/// a connect raised by a task on this shard. the reply carries a `!Send`
/// Connection, so it never crosses a thread boundary
pub(crate) struct ConnectRequest {
    pub peer: SocketAddr,
    pub server_name: rustls::pki_types::ServerName<'static>,
    pub reply: oneshot::Sender<Connection>,
}

/// shard configuration
pub(crate) struct ShardConfig {
    pub is_server: bool,
    pub server_config: Option<Arc<rustls::ServerConfig>>,
    pub client_config: Option<Arc<rustls::ClientConfig>>,
    pub hmac: ring::hmac::Key,
    pub endpoint: EndpointConfig,
    pub handler: Option<Handler>,
}

/// everything a connection reaches back into on its own shard. held by `Rc`, so
/// touching it costs a non-atomic refcount and never leaves the core
pub(crate) struct ShardCore {
    /// runs the connection and application tasks
    pub exec: LocalExec,

    /// connections with pending egress
    pub pending: RefCell<VecDeque<usize>>,

    /// tasks handlers spawned, adopted into their connection's slot each turn so
    /// closing the connection cancels them
    pub spawned: RefCell<Vec<(usize, Task<()>)>>,

    /// connects raised by local tasks, drained each turn
    pub connects: RefCell<Vec<ConnectRequest>>,

    /// pool for work that must not run on a shard
    pub offload: Arc<Offload>,
}

/// holds a connection and all needed data to be handled by the endpoint shard
struct ShardSlot {
    /// connection state
    conn: Rc<ConnState>,

    /// next deadline to act on
    scheduled: Option<Instant>,

    /// used to recognise stale timeout values
    generation: u64,

    /// active cids that map to this slot
    cids: Vec<cid::Id>,

    /// handler and stream tasks. they own a Connection, so they must live outside
    /// ConnState or the Rc would form a cycle and never drop
    tasks: Vec<Task<()>>,
}

impl ShardSlot {
    fn new(conn: Rc<ConnState>, initial_cid: cid::Id) -> Self {
        ShardSlot {
            conn,
            scheduled: None,
            generation: 0,
            cids: vec![initial_cid],
            tasks: Vec::new(),
        }
    }
}

/// used to identify packet shard destination
enum Route {
    Local,
    Forward(u8),
}

/// presents an independant slice of an endpoint. works on its own but may work with other
/// shards in parallel. each shard owns a distinct set of connections. packets that are
/// misrouted by accident, i.e. the peer changes its address and linux doesnt recognize the
/// tuple hash, are forwarded to the correct shard by using the id. the shard id is encoded
/// in the connection id of the respective connections, allowing for easy routing
pub(crate) struct Shard {
    /// local shard id
    id: u8,

    /// io handler
    io: Io,

    /// local address
    local_addr: SocketAddr,

    /// local config
    config: Arc<ShardConfig>,

    /// shard-local state connections reach back into
    core: Rc<ShardCore>,

    /// all connections that are held by this shard
    conns: Slab<ShardSlot>,

    /// connection id to index map
    by_dcid: HashMap<cid::Id, usize>,

    /// lazy-deletion timer heap (deadline, slab_key, generation)
    timers: BinaryHeap<Reverse<(Instant, usize, u64)>>,

    /// cross-thread inbox
    inbox: Receiver<ShardMsg>,

    /// siblings (other shards) to forward misrouted packets to
    siblings: Arc<[Mailbox]>,

    /// receive notifications from owned connections
    self_mbox: Mailbox,

    /// client: handles to awaiting established connection handles inside applicaton
    pending_connects: HashMap<cid::Id, oneshot::Sender<Connection>>,

    /// client: the application's root task, only ever on shard 0. it finishing
    /// tears the endpoint down
    root_task: Option<Task<()>>,

    /// flags turns that a handler blocked
    watchdog: Watchdog,

    /// reused per-turn scratch
    scratch: Vec<RecvBuf>,

    /// if the shard should shut down
    shutdown: bool,

    /// client: root task done, closing connections, shutdown only when drained
    winding_down: bool,
}

impl Shard {
    fn new(
        id: u8,
        io: Io,
        local_addr: SocketAddr,
        config: Arc<ShardConfig>,
        core: Rc<ShardCore>,
        inbox: Receiver<ShardMsg>,
        siblings: Arc<[Mailbox]>,
        self_mbox: Mailbox,
    ) -> Self {
        let watchdog = Watchdog::new(config.endpoint.turn_warn);
        Shard {
            id,
            io,
            local_addr,
            config,
            core,
            conns: Slab::new(),
            by_dcid: HashMap::new(),
            timers: BinaryHeap::new(),
            inbox,
            siblings,
            self_mbox,
            pending_connects: HashMap::new(),
            root_task: None,
            watchdog,
            scratch: Vec::with_capacity(64),
            shutdown: false,
            winding_down: false,
        }
    }

    /// synchronous event loop, stops when shutdown is received
    fn run(mut self) -> io::Result<()> {
        loop {
            if self.shutdown {
                return Ok(());
            }

            let deadline = self.next_deadline();

            // arm the flag before the emptiness check: anything scheduled in the
            // window between here and the poll finds parked == true, writes the
            // eventfd, and the poll returns on it at once
            self.self_mbox.parked.store(true, Ordering::SeqCst);

            let idle = self.inbox.is_empty()
                && self.core.exec.is_empty()
                && self.core.pending.borrow().is_empty();

            let wait = if idle {
                deadline
            } else {
                self.self_mbox.parked.store(false, Ordering::SeqCst);
                Some(Instant::now())
            };

            // blocking wait on one of (socket, waker fd, deadline)
            self.scratch.clear();
            self.io.poll(&mut self.scratch, wait)?;
            self.self_mbox.parked.store(false, Ordering::SeqCst);

            let now = Instant::now();

            let mut batch = std::mem::take(&mut self.scratch);
            for dg in batch.drain(..) {
                let (src, ecn, seg) = (dg.src(), dg.ecn(), dg.segment_size());
                let mut dg = dg;
                for datagram in dg.data_mut().chunks_mut(seg.unwrap_or(usize::MAX)) {
                    match route(datagram, self.id, self.siblings.len()) {
                        Route::Local => self.deliver(datagram, src, ecn),
                        Route::Forward(sid) => {
                            tracing::debug!(to = sid, src = %src, "forwarding misrouted datagram");
                            let fwd = ForwardedDatagram {
                                data: (*datagram).into(),
                                src,
                                ecn,
                            };
                            self.siblings[sid as usize].send(ShardMsg::Forwarded(fwd));
                        }
                    }
                }
            }
            self.scratch = batch;

            // poll cross-shard messages
            while let Ok(msg) = self.inbox.try_recv() {
                self.handle_msg(msg);
            }

            // fire every due timer (pto, idle, loss detection, ack, pacing)
            while let Some(key) = self.pop_due(now) {
                let Some(slot) = self.conns.get(key) else {
                    continue;
                };
                let conn = slot.conn.clone();
                conn.inner.borrow_mut().handle_timeout(now);
                conn.mark_pending();
            }

            // run connection and application tasks
            self.core.exec.drain(self.config.endpoint.task_budget);

            self.adopt_spawned();
            self.drain_connects();

            if let Some(task) = &mut self.root_task {
                if executor::try_join(task).is_some() {
                    self.root_task = None;
                    self.begin_shutdown();
                }
            }

            self.drain_egress();

            // client wind-down
            if self.winding_down && self.conns.is_empty() {
                self.shutdown = true;
                for m in self.siblings.iter() {
                    m.send(ShardMsg::Shutdown);
                }
            }

            self.maybe_compact_timers();
            self.io.flush()?;

            self.watchdog.turn(now, &self.core.exec);
        }
    }

    fn begin_shutdown(&mut self) {
        self.winding_down = true;

        for (_key, slot) in self.conns.iter() {
            slot.conn.inner.borrow_mut().begin_close(0x00, None);
            slot.conn.wake_all();
            slot.conn.mark_pending();
        }
    }

    /// process one datagram for a local connection
    fn deliver(&mut self, data: &mut [u8], src: SocketAddr, ecn: u8) {
        if data.is_empty() {
            return;
        }

        tracing::trace!(len = data.len(), src = %src, ecn, "datagram in");

        let dcid = match Header::peek_dcid(data, LOCAL_CID_LEN) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(len = data.len(), src = %src, error = %e, "malformed packet header, dropping");
                return;
            }
        };

        if let Some(&key) = self.by_dcid.get(dcid) {
            let conn = self.conns[key].conn.clone();
            let events = {
                let mut inner = conn.inner.borrow_mut();
                if let Err(e) = inner.recv(data, src, self.local_addr, ecn) {
                    tracing::error!(cid = %conn.internal_id, error = %e, "connection recv failed");
                }
                inner.poll_events()
            };
            self.apply_events(key, events);
            conn.mark_pending();
        } else if let Some(server_config) = self.config.server_config.clone() {
            match Inner::accept(
                data,
                src,
                self.local_addr,
                server_config,
                &self.config.hmac,
                self.id,
            ) {
                Ok((inner, cid)) => {
                    if self.winding_down {
                        tracing::debug!(src = %src, "shutting down, dropping new connection attempt");
                        return;
                    }

                    let key = self.insert(inner, cid);
                    tracing::info!(cid = %cid, src = %src, conns = self.conns.len(), "accepted new connection try");
                    let events = self.conns[key].conn.inner.borrow_mut().poll_events();
                    self.apply_events(key, events);
                    self.conns[key].conn.mark_pending();
                }
                Err(e) => tracing::debug!(src = %src, error = %e, "rejecting initial packet"),
            }
        } else {
            tracing::debug!(dcid = %format_args!("{:02x?}", dcid), src = %src, "no connection for dcid, dropping packet");
        }
    }

    /// take ownership of a new connection, the key is only valid once set on the
    /// state itself, since a task marks egress through it
    fn insert(&mut self, inner: Inner, cid: cid::Id) -> usize {
        let conn = Rc::new(ConnState::new(inner, cid, self.core.clone()));
        let key = self.conns.insert(ShardSlot::new(conn.clone(), cid));
        conn.key.set(key);
        self.by_dcid.insert(cid, key);
        key
    }

    fn apply_events(&mut self, key: usize, events: Vec<InnerEvent>) {
        let Some(slot) = self.conns.get_mut(key) else {
            return;
        };
        let conn = slot.conn.clone();

        for ev in events {
            match ev {
                InnerEvent::ConnectionEstablished => {
                    let connection = Connection {
                        state: conn.clone(),
                    };
                    let id = connection.state.internal_id;
                    tracing::info!(cid = %id, "connection established");

                    if self.config.is_server {
                        if let Some(handler) = self.config.handler.clone() {
                            let span = tracing::info_span!("conn", cid = %id);
                            let task = self.core.exec.spawn(
                                async move {
                                    handler(connection.clone()).await;
                                    connection.close(0x00, None).await;
                                }
                                .instrument(span),
                            );
                            slot.tasks.push(task);
                        }
                    } else if let Some(reply) = self.pending_connects.remove(&id) {
                        if reply.send(connection).is_err() {
                            tracing::debug!(cid = %id, "nobody is waiting for this connection");
                        }
                    }
                }
                InnerEvent::NewConnectionId(ncid) => {
                    tracing::debug!(cid = %ncid, "issued connection id");
                    self.by_dcid.insert(ncid, key);
                    slot.cids.push(ncid);
                }
                InnerEvent::RetireConnectionId(rcid) => {
                    tracing::debug!(cid = %rcid, "retired connection id");
                    self.by_dcid.remove(&rcid);
                    slot.cids.retain(|c| *c != rcid);
                }
                InnerEvent::ClosedByPeer => {
                    let lconn = conn.clone();
                    tracing::info!(cid = %lconn.internal_id, "closed by peer");
                    lconn.wake_all();
                    lconn.mark_pending();
                }
                InnerEvent::StreamOpenable(i) | InnerEvent::StreamAcceptable(i) => {
                    if let Some(w) = conn.wakers.borrow_mut().streams[i as usize].take() {
                        w.wake()
                    }
                }
                InnerEvent::StreamReadable(id) => {
                    if let Some(w) = conn.wakers.borrow_mut().read.remove(&id) {
                        w.wake()
                    }
                }
                InnerEvent::StreamWritable(id) => {
                    if let Some(w) = conn.wakers.borrow_mut().write.remove(&id) {
                        w.wake()
                    }
                }
                InnerEvent::StreamFinished(id) => {
                    if let Some(w) = conn.wakers.borrow_mut().finished.remove(&id) {
                        w.wake()
                    }
                }
            }
        }
    }

    fn handle_msg(&mut self, msg: ShardMsg) {
        match msg {
            ShardMsg::Forwarded(mut fwd) => {
                let (src, ecn) = (fwd.src, fwd.ecn);
                self.deliver(&mut fwd.data, src, ecn);
            }
            ShardMsg::Shutdown => {
                tracing::info!(conns = self.conns.len(), "shutdown requested");
                self.begin_shutdown();
            }
        }
    }

    /// move tasks a handler spawned into their connection's slot. a task whose
    /// connection already went away is simply dropped, which cancels it
    fn adopt_spawned(&mut self) {
        for (key, task) in self.core.spawned.borrow_mut().drain(..) {
            match self.conns.get_mut(key) {
                Some(slot) => slot.tasks.push(task),
                None => drop(task),
            }
        }
    }

    /// start the connects local tasks raised during this turn
    fn drain_connects(&mut self) {
        let reqs: Vec<ConnectRequest> = self.core.connects.borrow_mut().drain(..).collect();
        for req in reqs {
            let Some(client_config) = self.config.client_config.clone() else {
                continue; // not a client
            };

            match Inner::connect(
                req.peer,
                self.local_addr,
                req.server_name,
                client_config,
                &self.config.hmac,
                self.id,
            ) {
                Ok((inner, cid)) => {
                    let key = self.insert(inner, cid);
                    tracing::info!(cid = %cid, peer = %req.peer, "connecting to {}", req.peer);
                    self.pending_connects.insert(cid, req.reply);
                    self.conns[key].conn.mark_pending();
                }
                Err(e) => {
                    tracing::error!(peer = %req.peer, error = %e, "failed to connect to {}", req.peer)
                }
            }
        }
    }

    /// serialise every pending connection into the send ring. with GSO a batch
    /// holds several equal-sized datagrams that the kernel re-cuts, so segments are
    /// packed until one comes back short, which must be the last in the buffer
    fn drain_egress(&mut self) {
        let seg = self.config.endpoint.mtu;
        let burst = self.config.endpoint.tx_burst;

        let n = self.core.pending.borrow().len();
        for _ in 0..n {
            let Some(key) = self.core.pending.borrow_mut().pop_front() else {
                break;
            };
            let Some(slot) = self.conns.get(key) else {
                continue;
            };

            let conn = slot.conn.clone();
            conn.queued.set(false);

            let (events, deadline, closed, more) = {
                let mut inner = conn.inner.borrow_mut();
                let dest = inner.get_current_path();
                let mut emitted = 0usize;

                let more = loop {
                    if emitted >= burst {
                        break true;
                    }

                    // no send buffer left, retry next turn
                    let Some(mut batch) = self.io.begin(seg) else {
                        tracing::warn!(cid = %conn.internal_id, "send ring exhausted, deferring egress");
                        break true;
                    };

                    let dry = loop {
                        let Some(buf) = batch.segment(seg) else {
                            break false; // batch is full
                        };

                        match inner.fetch_dgram(buf) {
                            Ok(0) => break true,
                            Ok(len) => {
                                batch.commit(len);
                                emitted += 1;

                                // a short datagram must be the last of a gso buffer
                                if len < seg || emitted >= burst {
                                    break false;
                                }
                            }
                            Err(e) => {
                                tracing::error!(cid = %conn.internal_id, error = %e, "fetch_dgram failed");
                                break true;
                            }
                        }
                    };

                    if !batch.is_empty() {
                        tracing::trace!(
                            cid = %conn.internal_id,
                            dest = %dest,
                            segments = batch.count(),
                            bytes = batch.len(),
                            "sending datagrams"
                        );
                        self.io.enqueue(batch, dest, seg);
                    }

                    if dry {
                        break false;
                    }
                };

                (
                    inner.poll_events(),
                    inner.timeout(),
                    inner.is_closed(),
                    more,
                )
            };

            self.apply_events(key, events);

            if closed {
                // TODO inform all currently saved wakers via and emit an error in the poll
                // functions so that any client or server function can safely return and doesnt wait
                // forever
                self.drop_connection(key);
                continue;
            }

            if more {
                conn.mark_pending();
            }

            self.reschedule(key, deadline);
        }
    }

    fn reschedule(&mut self, key: usize, deadline: Option<Instant>) {
        if let Some(slot) = self.conns.get_mut(key) {
            if slot.scheduled != deadline {
                slot.scheduled = deadline;
                slot.generation = slot.generation.wrapping_add(1);
                if let Some(d) = deadline {
                    let lgen = slot.generation;
                    self.timers.push(Reverse((d, key, lgen)));
                }
            }
        }
    }

    /// drop stale heap entries
    fn purge_stale(&mut self) {
        while let Some(&Reverse((dl, key, generation))) = self.timers.peek() {
            let live = matches!(
                self.conns.get(key),
                Some(slot) if slot.generation == generation && slot.scheduled == Some(dl)
            );

            if live {
                break;
            }

            self.timers.pop();
        }
    }

    fn next_deadline(&mut self) -> Option<Instant> {
        self.purge_stale();
        self.timers.peek().map(|&Reverse((dl, _, _))| dl)
    }

    fn pop_due(&mut self, now: Instant) -> Option<usize> {
        self.purge_stale();

        match self.timers.peek().copied() {
            Some(Reverse((dl, key, _))) if dl <= now => {
                self.timers.pop();

                if let Some(slot) = self.conns.get_mut(key) {
                    slot.scheduled = None;
                }

                Some(key)
            }
            _ => None,
        }
    }

    fn maybe_compact_timers(&mut self) {
        let live = self.conns.len();
        if self.timers.len() <= 4 * live + 16 {
            return;
        }

        let old = std::mem::take(&mut self.timers);
        let conns = &self.conns;
        self.timers = old
            .into_iter()
            .filter(|Reverse((dl, key, generation))| {
                matches!(conns.get(*key), Some(s) if s.generation == *generation && s.scheduled == Some(*dl))
            })
            .collect();
    }

    /// removing the slot drops its tasks, which cancels the handler and every
    /// stream task it spawned, which in turn releases the last Connection
    fn drop_connection(&mut self, key: usize) {
        if let Some(slot) = self.conns.try_remove(key) {
            tracing::info!(
                cid = %slot.conn.internal_id,
                tasks = slot.tasks.len(),
                conns = self.conns.len(),
                "connection closed, dropping"
            );

            for c in &slot.cids {
                self.by_dcid.remove(c);
            }
            self.pending_connects.remove(&slot.conn.internal_id);
        }
    }
}

/// check whether a datagram belongs to this shard from its dcids first byte
/// long-header packets are always handled locally
#[inline]
fn route(data: &[u8], id: u8, shards: usize) -> Route {
    match data.first() {
        Some(&b0) if b0 & 0x80 == 0 => match data.get(1).copied() {
            Some(sid) if sid != id && (sid as usize) < shards => Route::Forward(sid),
            _ => Route::Local,
        },
        _ => Route::Local,
    }
}

/// main endpoint struct. owns the thread handles of all its shards and holds a handle
/// into every shard
pub struct ShardedEndpoint {
    /// handle into every owned shard
    mailboxes: Arc<[Mailbox]>,

    /// the set of thread handles the shards run on
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl ShardedEndpoint {
    pub fn shutdown(&self) {
        for m in self.mailboxes.iter() {
            m.send(ShardMsg::Shutdown);
        }
    }

    pub fn sync_shutdown(&mut self) {
        self.shutdown();
        self.wait();
    }

    /// block the caller until every shard has exited
    pub fn wait(&mut self) {
        for h in self.threads.drain(..) {
            let _ = h.join();
        }
    }
}

impl Drop for ShardedEndpoint {
    fn drop(&mut self) {
        self.sync_shutdown();
    }
}

fn resolve_local_addr(addr: SocketAddr) -> io::Result<SocketAddr> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.bind(&addr.into())?;
    sock.local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("bound to a non-IP address"))
}

pub(crate) fn spawn(
    addr: SocketAddr,
    config: Arc<ShardConfig>,
    root: Option<RootFn>,
) -> io::Result<ShardedEndpoint> {
    // darwin's SO_REUSEPORT hands every datagram to the first socket bound to the
    // port instead of load balancing, so more than one shard does not make sense with
    // with a single unique socket
    let requested = config.endpoint.workers;
    let workers = if !config.is_server {
        if requested > 1 {
            tracing::warn!(
                requested,
                "client endpoints use a single shard, clamping to one"
            );
        }
        1
    } else if cfg!(target_vendor = "apple") && requested > 1 {
        tracing::warn!(
            requested,
            "darwin does not load balance SO_REUSEPORT, clamping to one worker"
        );
        1
    } else {
        requested
    };

    assert!(workers >= 1, "an endpoint needs at least one worker");
    assert!(
        workers <= u8::MAX as usize,
        "shard id must fit in one CID byte"
    );
    let resolved = resolve_local_addr(addr)?;

    // resolve cores
    let total = std::thread::available_parallelism().map_or(1, |n| n.get());
    let shard_cores = 0..workers.min(total);
    let offload_cores: Vec<usize> = (workers..(2*workers).min(total)).collect();

    if offload_cores.is_empty() {
        tracing::warn!("shard cores fully saturate cpu, no more left for offloading");
    }

    let offload_threads = if config.endpoint.offload_threads == 0 {
        workers
    } else {
        config.endpoint.offload_threads
    };
    let offload = Arc::new(Offload::new(offload_threads, &offload_cores)?);

    tracing::info!(
        addr = %resolved,
        workers,
        role = if config.is_server { "server" } else { "client" },
        shard_cores = ?shard_cores,
        offload_cores = ?offload_cores,
        offload_threads,
        "endpoint starting"
    );

    let mut rxs = Vec::with_capacity(workers);
    let mut mboxes = Vec::with_capacity(workers);
    for _ in 0..workers {
        let waker = CrossThreadWaker::new()?;
        let (tx, rx) = crossbeam_channel::unbounded::<ShardMsg>();
        mboxes.push(Mailbox {
            tx,
            waker,
            parked: Arc::new(AtomicBool::new(false)),
        });
        rxs.push(rx);
    }
    let mailboxes: Arc<[Mailbox]> = Arc::from(mboxes);

    let mut root = root;
    let mut threads = Vec::with_capacity(workers);
    for (id, rx) in rxs.into_iter().enumerate() {
        let siblings = mailboxes.clone();
        let self_mbox = mailboxes[id].clone();
        let cfg = config.clone();
        let pool = offload.clone();
        let core_id = (id < total).then_some(id);
        let pin = cfg.endpoint.pin_cores;

        // only shard 0 runs the client's root future
        let my_root = if id == 0 { root.take() } else { None };

        let handle = std::thread::Builder::new()
            .name(format!("taurus-shard-{id}"))
            .spawn(move || {
                let _span = tracing::info_span!("shard", id).entered();

                if pin {
                    if let Some(c) = core_id {
                        match executor::pin_to_core(c) {
                            Ok(()) => tracing::debug!(core = c, "pinned to core"),
                            Err(e) => tracing::warn!(core = c, error = %e, "could not pin to core"),
                        }
                    }
                }

                let waker = self_mbox.waker.clone();
                let io = match Io::bind(resolved, &cfg.endpoint.io, waker.clone()) {
                    Ok(io) => io,
                    Err(e) => {
                        tracing::error!(error = %e, "socket bind failed");
                        return;
                    }
                };

                // the executor is !Send, so it is built here rather than handed in
                let core = Rc::new(ShardCore {
                    exec: LocalExec::new(self_mbox.parked.clone(), waker),
                    pending: RefCell::new(VecDeque::new()),
                    spawned: RefCell::new(Vec::new()),
                    connects: RefCell::new(Vec::new()),
                    offload: pool,
                });

                let local = io.local_addr().unwrap_or(resolved);
                let caps = io.capabilities();
                tracing::info!(
                    addr = %local,
                    backend = caps.backend,
                    gso = caps.gso,
                    gro = caps.gro,
                    "shard started"
                );

                let mut shard = Shard::new(
                    id as u8,
                    io,
                    local,
                    cfg,
                    core.clone(),
                    rx,
                    siblings.clone(),
                    self_mbox,
                );

                if let Some(root) = my_root {
                    let client = Client { core: core.clone() };
                    shard.root_task = Some(core.exec.spawn(root(client)));
                }

                match shard.run() {
                    Ok(()) => tracing::info!("shard stopped"),
                    Err(e) => {
                        tracing::error!(error = %e, "event loop terminated, shutting the endpoint down");
                        for m in siblings.iter() {
                            m.send(ShardMsg::Shutdown);
                        }
                    }
                }
            })?;
        threads.push(handle);
    }

    Ok(ShardedEndpoint { mailboxes, threads })
}
