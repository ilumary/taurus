use indexmap::IndexMap;
use intrusive_collections::{
    intrusive_adapter, rbtree::Cursor, KeyAdapter, LinkedList, LinkedListAtomicLink, RBTree,
    RBTreeAtomicLink,
};
use parking_lot::Mutex;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use std::{
    future,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use crate::{io, packet::Header, stream, terror, ConnectionId, ConnectionState, Inner, InnerEvent};

// received from a call to Client::connect(). resolves to the connection if successful
pub struct Connecting {
    rx: oneshot::Receiver<Connection>,
}

impl Future for Connecting {
    type Output = Option<Connection>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.rx).poll(cx) {
            Poll::Ready(Ok(value)) => Poll::Ready(Some(value)),
            Poll::Ready(Err(_)) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// holds single channel handle to send a client connect to the endpoint
pub struct Client {
    connector: mpsc::Sender<(SocketAddr, oneshot::Sender<Connection>)>,
}

impl Client {
    /// used to connect to an address. yields a connecting future which in turn yields
    /// [`Option<Connection>`]
    ///
    /// # Example
    ///
    /// ```
    /// use quic::connection::ClientConfig;
    ///
    /// async fn run_client() {
    ///     let mut client = quic::connection::ClientConfig::new("/path/to/cert.der")
    ///         .with_supported_protocols(vec!["hq-29".to_owned()])
    ///         .listen_on("[::1]:4433")
    ///         .build()
    ///         .await
    ///         .unwrap();
    ///     
    ///     if let Some(connection) = client.connect("[::1]:8080".parse().unwrap()).await {
    ///         println!("connected!");
    ///     }
    /// }
    ///
    /// ```
    pub fn connect(&mut self, to: SocketAddr) -> Connecting {
        let (conn_ready_tx, conn_ready_rx) = oneshot::channel();
        self.connector.try_send((to, conn_ready_tx)).unwrap();
        Connecting { rx: conn_ready_rx }
    }
}

pub struct ClientConfig {
    client_config: rustls::ClientConfig,
    listen_on: SocketAddr,
}

impl ClientConfig {
    pub fn new(cert_path: &str) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let mut roots = rustls::RootCertStore::empty();

        let cert = match std::fs::read(cert_path) {
            Ok(c) => CertificateDer::from(c),
            Err(e) => {
                panic!("failed to read client certificate: {}", e);
            }
        };

        debug!("loaded cert from {}", cert_path);

        if let Err(e) = roots.add(cert) {
            panic!("fatal error adding certificate to root store: {}", e);
        }

        let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();

        Self {
            client_config: client_cfg,
            listen_on: "[::1]:4433".parse().unwrap(),
        }
    }

    pub fn with_supported_protocols(mut self, protocols: Vec<String>) -> Self {
        self.client_config.alpn_protocols = protocols.into_iter().map(|p| p.into_bytes()).collect();
        self
    }

    pub fn with_key_log_file(mut self) -> Self {
        self.client_config.key_log = Arc::new(rustls::KeyLogFile::new());
        self
    }

    pub fn listen_on(mut self, addr: &str) -> Self {
        self.listen_on = addr.parse().unwrap();
        self
    }

    pub async fn build(self) -> Result<Client, terror::Error> {
        let (server_tx, _) = mpsc::channel::<Connection>(1);
        let (ncc_tx, ncc_rx) = mpsc::channel::<(SocketAddr, oneshot::Sender<Connection>)>(64);
        let hmac_reset_key = [0u8; 64];

        let endpoint = Endpoint {
            connections: ConnectionMap::new(),
            connection_ids: IndexMap::new(),
            server_config: None,
            client_config: Some(Arc::new(self.client_config)),
            hmac_reset_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &hmac_reset_key),
            nc_tx: server_tx,
            ncc_rx,
        };

        io::event_loop(self.listen_on, 1500, 8, 8, endpoint);

        Ok(Client { connector: ncc_tx })
    }
}

// server impl

struct Acceptor {
    rx: mpsc::Receiver<Connection>,
}

impl Acceptor {
    async fn accept(&mut self) -> Option<Connection> {
        self.rx.recv().await
    }
}

pub struct Server {
    acceptor: Acceptor,
    pub address: SocketAddr,
}

impl Server {
    /// pollable for incoming connections as a server. returns the established connection. If
    /// [`None`] is returned, an error occured during connection establishment.
    ///
    ///
    /// # Example
    ///
    /// ```
    /// use quic::connection::ServerConfig;
    ///
    /// async fn run_server() {
    ///     let mut server = quic::connection::ServerConfig::new(
    ///         "[::1]:4433", "/path/to/cert.der", "/path/to/key.der",
    ///     )
    ///     .with_supported_protocols(vec!["hq-29".to_owned()])
    ///     .build()
    ///     .await
    ///     .unwrap();
    ///     
    ///     while let Some(connection) = server.accept().await {
    ///         println!("connected!");
    ///     }
    /// }
    ///
    /// ```
    pub async fn accept(&mut self) -> Option<Connection> {
        self.acceptor.accept().await
    }
}

pub struct ServerConfig {
    server_config: rustls::ServerConfig,
    address: SocketAddr,
}

impl ServerConfig {
    pub fn new(addr: &str, cert_path: &str, key_path: &str) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let (cert, key) =
            match std::fs::read(cert_path).and_then(|x| Ok((x, std::fs::read(key_path)?))) {
                Ok((cert, key)) => (
                    CertificateDer::from(cert),
                    PrivateKeyDer::try_from(key).unwrap(),
                ),
                Err(e) => {
                    panic!("failed to read server certificate: {}", e);
                }
            };

        debug!("loaded cert from {} and key from {}", cert_path, key_path);

        let server_cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();

        ServerConfig {
            server_config: server_cfg,
            address: addr.parse().unwrap(),
        }
    }

    pub fn with_supported_protocols(mut self, protocols: Vec<String>) -> Self {
        self.server_config.alpn_protocols = protocols.into_iter().map(|p| p.into_bytes()).collect();
        self
    }

    pub async fn build(self) -> Result<Server, terror::Error> {
        let (new_connection_tx, new_connection_rx) = mpsc::channel::<Connection>(64);
        let (_, ncc_rx) = mpsc::channel::<(SocketAddr, oneshot::Sender<Connection>)>(1);
        let hmac_reset_key = [0u8; 64];

        let endpoint = Endpoint {
            connections: ConnectionMap::new(),
            connection_ids: IndexMap::new(),
            server_config: Some(Arc::new(self.server_config)),
            client_config: None,
            hmac_reset_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &hmac_reset_key),
            nc_tx: new_connection_tx,
            ncc_rx,
        };

        io::event_loop(self.address, 1500, 8, 8, endpoint);

        Ok(Server {
            address: self.address,
            acceptor: Acceptor {
                rx: new_connection_rx,
            },
        })
    }
}

// internal impl

intrusive_adapter!(ConnectionAdapter = Arc<LockedInner>: LockedInner { direct_link: RBTreeAtomicLink });
impl<'a> KeyAdapter<'a> for ConnectionAdapter {
    type Key = ConnectionId;
    fn get_key(&self, x: &'a LockedInner) -> ConnectionId {
        x.internal_id.clone()
    }
}

intrusive_adapter!(TransmissionPendingAdapter = Arc<LockedInner>:
    LockedInner { transmission_link: LinkedListAtomicLink });

intrusive_adapter!(ConnectionClosedAdapter = Arc<LockedInner>:
    LockedInner { closed_link: LinkedListAtomicLink });

struct ConnectionMap {
    // main connection list, sorted by connection id
    core: RBTree<ConnectionAdapter>,

    // holds all connections which have a pending transmission
    transmission_pending: LinkedList<TransmissionPendingAdapter>,

    // holds all closed connections, aka finished either gracefull or by termination
    closed: LinkedList<ConnectionClosedAdapter>,
}

impl ConnectionMap {
    pub fn new() -> Self {
        Self {
            core: RBTree::new(ConnectionAdapter::new()),
            transmission_pending: LinkedList::new(TransmissionPendingAdapter::new()),
            closed: LinkedList::new(ConnectionClosedAdapter::new()),
        }
    }

    pub fn find_existing(&mut self, id: &ConnectionId) -> Option<Cursor<'_, ConnectionAdapter>> {
        let c = self.core.find(id);

        if c.is_null() {
            return None;
        }

        Some(c)
    }
}

pub(crate) struct Endpoint {
    // owns the actual connection objects
    connections: ConnectionMap,

    // internal connection id map, maps from external to internal id to support multiple external
    // ids to avoid reinserting and/or cloning the connection inside intrusive collections
    connection_ids: IndexMap<ConnectionId, ConnectionId>,

    // server config for rustls
    server_config: Option<Arc<rustls::ServerConfig>>,

    // client config for rustls
    client_config: Option<Arc<rustls::ClientConfig>>,

    // RFC 2104, used to generate reset tokens from connection ids
    hmac_reset_key: ring::hmac::Key,

    // channel for sending new connections. server only
    nc_tx: mpsc::Sender<Connection>,

    // channel for receiving new connecting attempts. client only
    ncc_rx: mpsc::Receiver<(SocketAddr, oneshot::Sender<Connection>)>,
}

impl Endpoint {
    pub fn recv(&mut self, mut recv_ref: thingbuf::mpsc::RecvRef<'_, (Vec<u8>, SocketAddr)>) {
        if recv_ref.0.is_empty() {
            warn!("Received empty datagram");
            return;
        }

        let path = recv_ref.1;

        info!("Received {:?} bytes from {:?}", recv_ref.0.len(), path);

        let mut partial_decode = match Header::from_bytes(&recv_ref.0, 8) {
            Ok(h) => h,
            Err(error) => {
                error!("error while decoding header: {}", error);
                return;
            }
        };

        debug!("I: {}", &partial_decode);

        let mut conn_ptr: Option<Arc<LockedInner>> = None;
        let mut events: Vec<InnerEvent> = Vec::new();

        if let Some(internal_id) = self.connection_ids.get(&partial_decode.dcid) {
            if let Some(cursor) = self.connections.find_existing(internal_id) {
                debug!("found connection");

                let arc_li = cursor.clone_pointer().unwrap();
                conn_ptr = Some(arc_li.clone());
                let mut conn = arc_li.lock();

                if let Err(error) = conn.recv(&mut recv_ref.0, &mut partial_decode, path) {
                    error!("error processing datagram: {}", error);
                }

                while let Some(event) = conn.poll_event() {
                    events.push(event);
                }
            }
        } else {
            // if we dont recgnise the dcid, assume its an inital packet
            let server_config = self.server_config.clone().unwrap();
            match Inner::accept(
                &mut recv_ref.0,
                path.to_string(),
                server_config,
                &self.hmac_reset_key,
            ) {
                Ok((inner, cid)) => {
                    debug!("accepted new connection");
                    let a_inner = Arc::new(LockedInner::from_inner(inner, cid.clone()));
                    conn_ptr = Some(a_inner.clone());
                    self.connections.core.insert(a_inner.clone());
                    self.connection_ids.insert(cid.clone(), cid);
                }
                Err(err) => {
                    error!("error processing initial packet: {}", err);
                }
            };
        }

        if let Some(c_ptr) = conn_ptr {
            for event in events {
                match event {
                    InnerEvent::ConnectionEstablished => {
                        let api = c_ptr.clone();
                        let sender = self.nc_tx.clone();

                        // TODO client
                        tokio::spawn(async move {
                            if let Err(e) = sender.send(Connection { api }).await {
                                error!("error sending new connection: {}", e);
                            }
                        });
                    }
                    InnerEvent::NewConnectionId(ncid) => {
                        self.connection_ids.insert(ncid, c_ptr.internal_id.clone());
                    }
                    InnerEvent::RetireConnectionId(ocid) => {
                        self.connection_ids.swap_remove(&ocid);
                    }
                    InnerEvent::ClosedByPeer => {
                        if c_ptr.direct_link.is_linked() {
                            unsafe {
                                self.connections
                                    .core
                                    .cursor_mut_from_ptr(Arc::as_ptr(&c_ptr))
                                    .remove();
                            }
                        }

                        if c_ptr.transmission_link.is_linked() {
                            unsafe {
                                self.connections
                                    .transmission_pending
                                    .cursor_mut_from_ptr(Arc::as_ptr(&c_ptr))
                                    .remove();
                            }
                        }

                        self.connections.closed.push_back(c_ptr.clone());
                    }
                }
            }

            // enqueue connection into pending transmissions
            self.connections
                .transmission_pending
                .push_back(c_ptr.clone());
        }
    }

    pub async fn iterate_transmission_pending<F, Fut>(
        &mut self,
        send_queues: Arc<[io::SendQueue]>,
        mut f: F,
    ) where
        F: FnMut(Arc<LockedInner>, io::SendQueue) -> Fut,
        Fut: Future<Output = bool> + Send + 'static,
    {
        let mut fut = Vec::new();
        {
            let mut current = self.connections.transmission_pending.front_mut();

            while !current.is_null() {
                let node = current.as_cursor().clone_pointer().unwrap();

                let send_queue = match send_queues.iter().find(|s| s.remaining() > 0) {
                    Some(s) => s,
                    None => break,
                };

                fut.push(f(node, send_queue.clone()));

                current.move_next();
            }
        }

        let results = futures::future::join_all(fut).await;

        let mut it = self.connections.transmission_pending.front_mut();
        let mut i: usize = 0;

        while !it.is_null() {
            if results[i] {
                it.remove();
            } else {
                it.move_next();
            }

            i += 1;
        }
    }

    pub fn poll_wakeups(&mut self, cx: &mut std::task::Context<'_>) -> Poll<bool> {
        // includes timeouts
        // includes connection attempts from client
        if self.client_config.is_some() {
            match self.ncc_rx.poll_recv(cx) {
                Poll::Ready(Some((dest_addr, ready_sender))) => {
                    let _cc = self.client_config.clone().unwrap();
                    // create new connection
                    // insert into core, transmission_pending
                    // return
                }
                Poll::Ready(None) => error!("fatal error receiving connection attempt"),
                Poll::Pending => (),
            }
        }
        // includes proactive data sending from application
        // returns poll of polls somehow
        Poll::Pending
    }
}

pub(crate) struct LockedInner {
    // actual connection implementation
    inner: Mutex<Inner>,

    // internal connection id used for lookup
    internal_id: ConnectionId,

    // rbtree link to main connection container
    direct_link: RBTreeAtomicLink,

    // links to rbtree containing all connections that are ready to transmit
    transmission_link: LinkedListAtomicLink,

    // links to list containing all closed connections
    closed_link: LinkedListAtomicLink,
}

impl LockedInner {
    pub fn from_inner(inner: Inner, id: ConnectionId) -> Self {
        Self {
            inner: Mutex::new(inner),
            internal_id: id,
            direct_link: RBTreeAtomicLink::default(),
            transmission_link: LinkedListAtomicLink::default(),
            closed_link: LinkedListAtomicLink::default(),
        }
    }

    pub fn lock(&self) -> parking_lot::lock_api::MutexGuard<'_, parking_lot::RawMutex, Inner> {
        self.inner.lock()
    }
}

impl ConnectionApi for LockedInner {
    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        s_id: &u64,
        buf: &mut [u8],
    ) -> Poll<Result<Option<usize>, terror::Error>> {
        let mut conn = self.inner.lock();
        let bytes_read = conn.stream_read(s_id, buf, cx.waker().clone())?;

        match bytes_read {
            Some(0) => Poll::Pending,
            _ => Poll::Ready(Ok(bytes_read)),
        }
    }

    fn poll_send(
        &self,
        _cx: &mut std::task::Context,
        s_id: &u64,
        buf: &[u8],
        fin: bool,
    ) -> Poll<Result<usize, terror::Error>> {
        let mut conn = self.inner.lock();
        Poll::Ready(conn.stream_write(*s_id, buf, fin))
    }

    fn poll_accept(
        &self,
        cx: &mut std::task::Context,
        stream_t: u64,
        arc: Connection,
    ) -> Poll<Result<(Option<stream::RecvStream>, Option<stream::SendStream>), terror::Error>> {
        let mut conn = self.inner.lock();

        if let Some(id) = conn.stream_accept(stream_t, cx.waker().clone()) {
            let mut ss: Option<stream::SendStream> = None;
            let rs: Option<stream::RecvStream> = Some(stream::RecvStream::new(id, arc.clone()));

            if stream_t == 0x00 {
                ss = Some(stream::SendStream::new(id, arc.clone()))
            }

            return Poll::Ready(Ok((rs, ss)));
        }

        Poll::Pending
    }

    fn close(&self, ec: u64, _reason: Option<&str>) {
        // TODO reason
        let mut conn = self.inner.lock();
        conn.apec = Some(ec);
        conn.state = ConnectionState::Closing;
    }

    fn application_protocol(&self) -> Option<String> {
        if let Some(alp) = self.inner.lock().tls_session.alpn_protocol() {
            return Some(String::from_utf8(alp.to_vec()).unwrap());
        }
        None
    }

    fn keep_alive(&self, _enable: bool) {
        todo!("Connection keep alive has not yet been implemented");
    }

    fn zero_rtt(&self, _enable: bool) {
        todo!("zero_rtt enabling/disabling has not yet been implemented");
    }
}

pub struct Connection {
    pub(crate) api: Arc<dyn ConnectionApi>,
}

impl Connection {
    pub async fn accept_bidirectional_stream(
        &self,
    ) -> Result<(stream::RecvStream, stream::SendStream), terror::Error> {
        let s = future::poll_fn(|cx| self.api.poll_accept(cx, 0x00, self.clone())).await?;
        Ok((s.0.unwrap(), s.1.unwrap()))
    }

    pub async fn accept_unidirectional_stream(&self) -> Result<stream::RecvStream, terror::Error> {
        let s = future::poll_fn(|cx| self.api.poll_accept(cx, 0x02, self.clone())).await?;
        Ok(s.0.unwrap())
    }

    pub async fn open_bidirectional_stream(
        &self,
    ) -> Result<(stream::RecvStream, stream::SendStream), terror::Error> {
        todo!()
    }

    pub async fn open_unidirectional_stream(&self) -> Result<stream::RecvStream, terror::Error> {
        todo!()
    }

    pub async fn close(&self, ec: u64, reason: Option<&str>) {
        self.api.close(ec, reason);
    }

    pub fn application_protocol(&self) -> Option<String> {
        self.api.application_protocol()
    }
}

impl Clone for Connection {
    fn clone(&self) -> Self {
        Self {
            api: self.api.clone(),
        }
    }
}

pub(crate) trait ConnectionApi: Send + Sync {
    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        id: &u64,
        buf: &mut [u8],
    ) -> Poll<Result<Option<usize>, terror::Error>>;

    fn poll_send(
        &self,
        cx: &mut std::task::Context,
        id: &u64,
        buf: &[u8],
        fin: bool,
    ) -> Poll<Result<usize, terror::Error>>;

    fn poll_accept(
        &self,
        cx: &mut std::task::Context,
        _stream_t: u64,
        _arc: Connection,
    ) -> Poll<Result<(Option<stream::RecvStream>, Option<stream::SendStream>), terror::Error>>;

    fn close(&self, ec: u64, reason: Option<&str>);

    fn application_protocol(&self) -> Option<String>;

    fn keep_alive(&self, enable: bool);

    fn zero_rtt(&self, enable: bool);
}
