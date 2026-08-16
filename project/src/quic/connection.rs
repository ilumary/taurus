use rustc_hash::FxHashMap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::sync::oneshot;

use std::{
    cell::{Cell, RefCell},
    future,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use crate::{
    cid,
    endpoint::{
        self, ConnectRequest, EndpointConfig, Handler, ShardConfig, ShardCore, ShardedEndpoint,
    },
    stream, terror, Inner,
};

/// received from a call to Client::connect(). resolves to the connection if successful
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

/// handed to the client's root future. lives on shard 0 and is `!Send`, so every
/// connection it opens is owned by the shard the root future runs on
pub struct Client {
    pub(crate) core: Rc<ShardCore>,
}

impl Client {
    /// used to connect to an ip address. yields a connecting future which in turn yields
    /// [`Option<Connection>`]
    ///
    /// # Example
    ///
    /// ```ignore
    /// use quic::connection::ClientConfig;
    ///
    /// fn main() -> Result<(), quic::terror::Error> {
    ///     quic::connection::ClientConfig::new("/path/to/cert.der")
    ///         .with_supported_protocols(vec!["hq-29".to_owned()])
    ///         .listen_on("[::1]:4433")
    ///         .run(|client| async move {
    ///             if let Some(connection) = client.connect("[::1]:8080".parse().unwrap()).await {
    ///                 println!("connected!");
    ///             }
    ///         })
    /// }
    /// ```
    pub fn connect(&self, to: SocketAddr) -> Connecting {
        let (reply, rx) = oneshot::channel();
        let hostname = match to.ip() {
            std::net::IpAddr::V4(ipv4) if ipv4.is_loopback() => "localhost".to_string(),
            std::net::IpAddr::V6(ipv6) if ipv6.is_loopback() => "localhost".to_string(),
            ip => ip.to_string(),
        };

        let server_name = ServerName::try_from(hostname.to_owned()).unwrap();

        tracing::debug!(peer = %to, name = %hostname, "connect requested");

        self.core.connects.borrow_mut().push(ConnectRequest {
            peer: to,
            server_name,
            reply,
        });

        Connecting { rx }
    }

    /// used to connect to an actual hostname and port. Convenience implementation to
    /// to wrap dns hostname lookup, therefore async. Custom timeout may be specified
    /// in seconds via the `dns_timeout` param. Yields a connecting future which
    /// in turn yields [`Option<Connection>`]
    ///
    /// the lookup itself runs on the offload pool, never on the shard, because a
    /// shard thread has no dns resolver driving it
    pub async fn connect_to_hostname(
        &self,
        hostname: &str,
        port: u16,
        dns_timeout: u64,
    ) -> Result<Connecting, terror::Error> {
        let host = hostname.to_owned();
        let addrs = self
            .core
            .offload
            .run(async move {
                let lookup = tokio::net::lookup_host((host, port));
                match tokio::time::timeout(Duration::from_secs(dns_timeout), lookup).await {
                    Ok(Ok(it)) => Ok(it.collect::<Vec<SocketAddr>>()),
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(_) => Err(String::new()),
                }
            })
            .await;

        let addr = match addrs {
            Ok(list) => list.into_iter().next().ok_or_else(|| {
                terror::Error::dns_lookup_error(format!("no addresses found for {hostname}:{port}"))
            })?,
            Err(e) if e.is_empty() => {
                return Err(terror::Error::dns_timeout(format!(
                    "timout during dns resolution for {hostname}:{port}"
                )))
            }
            Err(e) => {
                return Err(terror::Error::dns_lookup_error(format!(
                    "dns resolution failed for {hostname}:{port}: {e}"
                )))
            }
        };

        let (reply, rx) = oneshot::channel();
        let server_name = ServerName::try_from(hostname.to_owned()).map_err(|e| {
            terror::Error::taurus_misc_error(format!("failed to parse {hostname}: {e}"))
        })?;

        self.core.connects.borrow_mut().push(ConnectRequest {
            peer: addr,
            server_name,
            reply,
        });

        Ok(Connecting { rx })
    }

    /// run a `Send` future on the offload pool and await it here
    ///
    /// ```ignore
    /// let body = client.offload(async { tokio::fs::read("payload.bin").await }).await?;
    /// ```
    pub async fn offload<F>(&self, fut: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.core.offload.run(fut).await
    }
}

pub struct ClientConfig {
    client_config: rustls::ClientConfig,
    listen_on: SocketAddr,
    endpoint: EndpointConfig,
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

        tracing::debug!("loaded cert from {}", cert_path);

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
            endpoint: EndpointConfig::default(),
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

    /// every backend knob at once, for callers who care
    pub fn with_config(mut self, config: EndpointConfig) -> Self {
        self.endpoint = config;
        self
    }

    /// runs the provided function on a single sharded endpoint. if the provided function returns,
    /// all currently active connections are closed gracefully and run() returns normally.
    /// equivalent to calling spawn() and then wait() on the endpoint handle
    ///
    /// # Example
    ///
    /// ```no_run
    /// use quic::connection::ClientConfig;
    ///
    /// fn main() -> Result<(), quic::terror::Error> {
    ///     ClientConfig::new("/path/to/cert.der")
    ///         .with_supported_protocols(vec!["hq-29".to_owned()])
    ///         .listen_on("[::1]:0")
    ///         .run(|client| async move {
    ///             let Some(conn) = client.connect("[::1]:4433".parse().unwrap()).await else {
    ///                 eprintln!("handshake failed");
    ///                 return;
    ///             };
    ///
    ///             // reading the payload off disk would block the shard, so offload it
    ///             let body = client
    ///                 .offload(async { tokio::fs::read("payload.bin").await.unwrap() })
    ///                 .await;
    ///
    ///             if let Ok((recv, send)) = conn.accept_bidirectional_stream().await {
    ///                 let _ = send.write(&body, true).await;
    ///                 let mut buf = [0u8; 1024];
    ///                 while let Ok(Some(n)) = recv.read(&mut buf).await {
    ///                     println!("{:?}", std::str::from_utf8(&buf[..n]));
    ///                 }
    ///             }
    ///         })
    /// }
    /// ```
    pub fn run<F, Fut>(self, root: F) -> Result<(), terror::Error>
    where
        F: FnOnce(Client) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        let mut endpoint = self.spawn(root)?;
        endpoint.wait();
        Ok(())
    }

    /// runs the provided function on a single sharded endpoint. run returns the [`ShardedEnpoint`]
    /// immediately.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use quic::connection::ClientConfig;
    /// use quic::terror::Error;
    ///
    /// fn main() -> Result<(), quic::terror::Error> {
    ///     let mut endpoint = ClientConfig::new("/path/to/cert.der")
    ///         .with_supported_protocols(vec!["hq-29".to_owned()])
    ///         .listen_on("[::1]:0")
    ///         .spawn(|client| async move {
    ///             let Some(conn) = client.connect("[::1]:4433".parse().unwrap()).await else {
    ///                 eprintln!("handshake failed");
    ///                 return;
    ///             };
    ///
    ///             // reading the payload off disk would block the shard, so offload it
    ///             let body = client
    ///                 .offload(async { tokio::fs::read("payload.bin").await.unwrap() })
    ///                 .await;
    ///
    ///             if let Ok((recv, send)) = conn.accept_bidirectional_stream().await {
    ///                 let _ = send.write(&body, true).await;
    ///                 let mut buf = [0u8; 1024];
    ///                 while let Ok(Some(n)) = recv.read(&mut buf).await {
    ///                     println!("{:?}", std::str::from_utf8(&buf[..n]));
    ///                 }
    ///             }
    ///         })?;
    ///     // do some work here
    ///     let test = 1 + 2;
    ///
    ///     // await endpoint completion
    ///     endpoint.wait();
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn spawn<F, Fut>(self, root: F) -> Result<ShardedEndpoint, terror::Error>
    where
        F: FnOnce(Client) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        let hmac_reset_key = [0u8; 64];
        let config = Arc::new(ShardConfig {
            is_server: false,
            server_config: None,
            client_config: Some(Arc::new(self.client_config)),
            hmac: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &hmac_reset_key),
            endpoint: self.endpoint,
            handler: None,
        });

        let root: endpoint::RootFn = Box::new(move |c| Box::pin(root(c)));

        let endpoint = endpoint::spawn(self.listen_on, config, Some(root)).map_err(|e| {
            terror::Error::taurus_misc_error(format!("failed to start endpoint: {e}"))
        })?;

        Ok(endpoint)
    }
}

// server impl

pub struct ServerConfig {
    server_config: rustls::ServerConfig,
    address: SocketAddr,
    endpoint: EndpointConfig,
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

        tracing::debug!("loaded cert from {} and key from {}", cert_path, key_path);

        let server_cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();

        ServerConfig {
            server_config: server_cfg,
            address: addr.parse().unwrap(),
            endpoint: EndpointConfig::default(),
        }
    }

    pub fn with_supported_protocols(mut self, protocols: Vec<String>) -> Self {
        self.server_config.alpn_protocols = protocols.into_iter().map(|p| p.into_bytes()).collect();
        self
    }

    pub fn with_workers(mut self, workers: usize) -> Self {
        self.endpoint.workers = workers.max(1);
        self
    }

    /// every backend knob at once, for callers who care
    pub fn with_config(mut self, config: EndpointConfig) -> Self {
        self.endpoint = config;
        self
    }

    /// run `handler` for every established connection and block until shutdown. as its a server it
    /// will continue to listen so this method will never return on its own, only via forceful
    /// process termination. equivalent to calling spawn() and wait() on the endpoint handle
    ///
    /// `handler` is cloned into every shard and invoked on the shard that owns the connection
    /// the moment its handshake completes. the future it returns is therefore `!Send` and spends
    /// its whole life on one core, next to the connection state it touches
    ///
    /// one handler task runs per connection. within a connection, spawn a task per stream with
    /// [`Connection::spawn`] so that a slow stream does not stall the accept loop
    ///
    /// the handler shares its thread with the packet loop for every other connection on that core.
    /// anything slow, e.g. a database call, a file read, heavy CPU, should go through
    /// [`Connection::offload`] or [`Connection::offload_blocking`], or those connections stall
    /// the others. see the module docs for the full rule. the watchdog will warn you when a turn
    /// overruns
    ///
    /// # Example
    ///
    /// ```no_run
    /// use quic::connection::ServerConfig;
    /// use quic::terror::Error;
    ///
    /// fn main() -> Result<(), quic::terror::Error> {
    ///     ServerConfig::new("[::1]:4433", "/path/to/cert.der", "/path/to/key.der")
    ///         .with_supported_protocols(vec!["hq-29".to_owned()])
    ///         .with_workers(4) // one shard per core
    ///         .run(|conn| async move {
    ///             // this future runs on the shard that owns `conn`
    ///             println!("{:?} connected", conn.application_protocol());
    ///
    ///             while let Ok((recv, send)) = conn.accept_bidirectional_stream().await {
    ///                 // one task per stream
    ///                 conn.spawn(|conn| async move {
    ///                     let mut buf = [0u8; 1024];
    ///                     while let Ok(Some(n)) = recv.read(&mut buf).await {
    ///                         let _ = send.write(&buf[..n], false).await;
    ///                     }
    ///                 });
    ///             }
    ///         })
    /// }
    /// ```
    pub fn run<F, Fut>(self, handler: F) -> Result<(), terror::Error>
    where
        F: Fn(Connection) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        let mut endpoint = self.spawn(handler)?;
        endpoint.wait();
        Ok(())
    }

    /// does the same as run(), only that it immediately returns and gives control over the endpoint
    /// handle. as its a server, it will continue to listen until either shutdown is called or the
    /// process exits. the endpoint handle will shutdown all shards when dropped.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use quic::connection::ServerConfig;
    /// use quic::terror::Error;
    ///
    /// fn main() -> Result<(), quic::terror::Error> {
    ///     let mut endpoint = ServerConfig::new("[::1]:4433", "/path/to/cert.der", "/path/to/key.der")
    ///         .with_supported_protocols(vec!["hq-29".to_owned()])
    ///         .with_workers(4) // one shard per core
    ///         .spawn(|conn| async move {
    ///             // this future runs on the shard that owns `conn`
    ///             println!("{:?} connected", conn.application_protocol());
    ///
    ///             while let Ok((recv, send)) = conn.accept_bidirectional_stream().await {
    ///                 // one task per stream
    ///                 conn.spawn(|conn| async move {
    ///                     let mut buf = [0u8; 1024];
    ///                     while let Ok(Some(n)) = recv.read(&mut buf).await {
    ///                         let _ = send.write(&buf[..n], false).await;
    ///                     }
    ///                 });
    ///             }
    ///         })?;
    ///     // do some work
    ///     let test = 1 + 2;
    ///
    ///     // wait and shutdown endpoint
    ///     endpoint.sync_shutdown();
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn spawn<F, Fut>(self, handler: F) -> Result<ShardedEndpoint, terror::Error>
    where
        F: Fn(Connection) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        let hmac_reset_key = [0u8; 64];
        let handler: Handler = Arc::new(move |conn| Box::pin(handler(conn)));

        let config = Arc::new(ShardConfig {
            is_server: true,
            server_config: Some(Arc::new(self.server_config)),
            client_config: None,
            hmac: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &hmac_reset_key),
            endpoint: self.endpoint,
            handler: Some(handler),
        });

        let endpoint = endpoint::spawn(self.address, config, None).map_err(|e| {
            terror::Error::taurus_misc_error(format!("failed to start endpoint: {e}"))
        })?;

        Ok(endpoint)
    }
}

/// mirrors the wakers struct inside the stream manager. stores actual task wakers that are fired if
/// an event is emitted in the endpoint after a packet is processed
#[derive(Default)]
pub(crate) struct StreamWakers {
    /// if accepting/initiating a stream was blocked
    pub streams: [Option<std::task::Waker>; 4],

    /// if reading from a stream was blocked
    pub read: FxHashMap<u64, std::task::Waker>,

    /// if writing to a stream was blocked
    pub write: FxHashMap<u64, std::task::Waker>,

    /// if a stream is finished, so fin bit set and all data sent and ack'ed
    pub finished: FxHashMap<u64, std::task::Waker>,
}

/// holds connection state. only ever touched by the shard that owns it
pub(crate) struct ConnState {
    /// internal connection id used for lookup
    pub internal_id: cid::Id,

    /// quic state machine
    pub inner: RefCell<Inner>,

    /// handle to the owning shard
    pub core: Rc<ShardCore>,

    /// slab key, set right after insertion
    pub key: Cell<usize>,

    /// true while the connection sits in the egress queue
    pub queued: Cell<bool>,

    /// stream wakers to enable async on stream events
    pub wakers: RefCell<StreamWakers>,

    /// cached from inner, for easy stream type construction
    pub side: u8,
}

impl ConnState {
    pub(crate) fn new(inner: Inner, id: cid::Id, core: Rc<ShardCore>) -> Self {
        let side = inner.side as u8;
        Self {
            internal_id: id,
            inner: RefCell::new(inner),
            core,
            key: Cell::new(usize::MAX),
            queued: Cell::new(false),
            wakers: RefCell::new(StreamWakers::default()),
            side,
        }
    }

    /// queue this connection for pending egress
    #[inline]
    pub(crate) fn mark_pending(&self) {
        if !self.queued.replace(true) {
            self.core.pending.borrow_mut().push_back(self.key.get());
        }
    }

    /// wakes all saved wakers
    pub(crate) fn wake_all(&self) {
        let mut w = self.wakers.borrow_mut();
        for s in w.streams.iter_mut() {
            if let Some(k) = s.take() {
                k.wake();
            }
        }
        for (_, k) in w.read.drain() {
            k.wake();
        }
        for (_, k) in w.write.drain() {
            k.wake();
        }
        for (_, k) in w.finished.drain() {
            k.wake();
        }
    }
}

/// a handle to one connection
pub struct Connection {
    pub(crate) state: Rc<ConnState>,
}

impl Connection {
    /// asynchronously accepts a new bidirectional stream
    ///
    /// ```ignore
    /// while let Ok((recv, send)) = connection.accept_bidirectional_stream().await {
    ///     connection.spawn(async move {
    ///         let mut buf = [0u8; 1024];
    ///         while let Ok(Some(n)) = recv.read(&mut buf).await {
    ///             let _ = send.write(&buf[..n], false).await;
    ///         }
    ///     });
    /// }
    /// ```
    pub async fn accept_bidirectional_stream(
        &self,
    ) -> Result<(stream::RecvStream, stream::SendStream), terror::Error> {
        let id = future::poll_fn(|cx| self.poll_accept(cx, 0x00)).await?;
        Ok((
            stream::RecvStream::new(id, self.clone()),
            stream::SendStream::new(id, self.clone()),
        ))
    }

    /// asynchronously accepts a new unirectional stream
    ///
    /// ```ignore
    /// while let Ok(recv) = connection.accept_unirectional_stream().await {
    ///     connection.spawn(async move {
    ///         let mut buf = [0u8; 1024];
    ///         while let Ok(Some(n)) = recv.read(&mut buf).await {
    ///             println!("read {n} bytes");
    ///         }
    ///     });
    /// }
    /// ```
    pub async fn accept_unidirectional_stream(&self) -> Result<stream::RecvStream, terror::Error> {
        let id = future::poll_fn(|cx| self.poll_accept(cx, 0x02)).await?;
        Ok(stream::RecvStream::new(id, self.clone()))
    }

    /// initiates a new bidirectional stream, may need to wait if the peers advertised max streams
    /// are fully utilized
    ///
    /// ```ignore
    /// let Ok((send, _recv)) = connection.open_bidirectional_stream().await else {
    ///     eprintln!("could not open stream");
    ///     return;
    /// };
    ///
    /// let bytes = "Hello World!".as_bytes();
    /// match send.write(bytes, true).await {
    ///     Ok(written) => println!("wrote {written} bytes to stream!"),
    ///     Err(e) => eprintln!("write failed: {e}"),
    /// }
    ///
    /// let mut buf = [0u8; 1024];
    /// if let Ok(Some(n)) = recv.read(&mut buf).await {
    ///     println!("read {n} bytes");
    /// }
    /// ```
    pub async fn open_bidirectional_stream(
        &self,
    ) -> Result<(stream::SendStream, stream::RecvStream), terror::Error> {
        let id = future::poll_fn(|cx| self.poll_open(cx, 0x00)).await?;
        Ok((stream::SendStream::new(id, self.clone()), stream::RecvStream::new(id, self.clone())))
    }

    /// initiates a new unirectional stream, may need to wait if the peers advertised max streams
    /// are fully utilized
    ///
    /// ```ignore
    /// let Ok((send, _recv)) = connection.open_bidirectional_stream().await else {
    ///     eprintln!("could not open stream");
    ///     return;
    /// };
    ///
    /// let bytes = "Hello World!".as_bytes();
    /// match send.write(bytes, true).await {
    ///     Ok(written) => println!("wrote {written} bytes to stream!"),
    ///     Err(e) => eprintln!("write failed: {e}"),
    /// }
    /// ```
    pub async fn open_unidirectional_stream(&self) -> Result<stream::SendStream, terror::Error> {
        let id = future::poll_fn(|cx| self.poll_open(cx, 0x02)).await?;
        Ok(stream::SendStream::new(id, self.clone()))
    }

    /// spawn a task on the shard that owns this connection
    ///
    /// used to fork per-stream work so a slow stream cannot stall the handler's accept loop.
    /// the task is owned by the connection: when the connection closes, it is cancelled and dropped
    ///
    /// ```ignore
    /// while let Ok((recv, send)) = conn.accept_bidirectional_stream().await {
    ///     conn.spawn(async move {
    ///         let mut buf = [0u8; 1024];
    ///         while let Ok(Some(n)) = recv.read(&mut buf).await {
    ///             let _ = send.write(&buf[..n], false).await;
    ///         }
    ///     });
    /// }
    /// ```
    pub fn spawn<F, Fut>(&self, f: F)
    where
        F: FnOnce(Connection) -> Fut,
        Fut: Future<Output = ()> + 'static,
    {
        let conn = self.clone();
        let task = self.state.core.exec.spawn(f(conn));
        self.state
            .core
            .spawned
            .borrow_mut()
            .push((self.state.key.get(), task));
    }

    /// run a `Send` future on the offload pool and await its result here
    ///
    /// ```ignore
    /// let rows = conn.offload(async move { pool.query(&sql).await }).await?;
    /// let resp = conn.offload(async move { request::get(url).await }).await?;
    /// ```
    pub async fn offload<F>(&self, fut: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.state.core.offload.run(fut).await
    }

    /// run blocking work on the offload pool and await its result here
    ///
    /// ```ignore
    /// let hash = conn.offload_blocking(move || argon2::hash(&password)).await;
    /// let file = conn.offload_blocking(move || std::fs::read("big.bin")).await?;
    /// ```
    pub async fn offload_blocking<T, F>(&self, f: F) -> T
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        self.state.core.offload.blocking(f).await
    }

    /// closes the connection. you may provide an error code or a reason. set the error code to 0 to
    /// indicate no error for a graceful teardown.
    pub async fn close(&self, ec: u64, reason: Option<&str>) {
        tracing::info!(cid = %self.state.internal_id, error_code = ec, reason = reason, "closing connection");
        self.state.inner.borrow_mut().begin_close(ec, reason);
        self.state.mark_pending();
    }

    /// returns the negotiated application protocol. will return [`None`] during handshake
    pub fn application_protocol(&self) -> Option<String> {
        if let Some(alp) = self.state.inner.borrow().tls_session.alpn_protocol() {
            return Some(String::from_utf8(alp.to_vec()).unwrap());
        }
        None
    }

    pub fn keep_alive(&self, _enable: bool) {
        todo!("Connection keep alive has not yet been implemented");
    }

    pub fn zero_rtt(&self, _enable: bool) {
        todo!("zero_rtt enabling/disabling has not yet been implemented");
    }

    pub(crate) fn poll_recv(
        &self,
        cx: &mut Context,
        s_id: &u64,
        buf: &mut [u8],
    ) -> Poll<Result<Option<usize>, terror::Error>> {
        let bytes_read = {
            let mut conn = self.state.inner.borrow_mut();
            if conn.is_closing() || conn.is_closed() {
                return match conn.apec.unwrap_or(0) {
                    0 => Poll::Ready(Ok(None)),
                    code => Poll::Ready(Err(terror::Error::connection_closed(format!(
                        "connection closed with: {}",
                        code
                    )))),
                };
            }
            match conn.stream_read(s_id, buf) {
                Ok(b) => b,
                Err(e) => return Poll::Ready(Err(e)),
            }
        };

        match bytes_read {
            Some(0) => {
                self.state
                    .wakers
                    .borrow_mut()
                    .read
                    .insert(*s_id, cx.waker().clone());
                Poll::Pending
            }
            _ => {
                self.state.mark_pending();
                Poll::Ready(Ok(bytes_read))
            }
        }
    }

    pub(crate) fn poll_finished(
        &self,
        cx: &mut Context,
        s_id: &u64,
    ) -> Poll<Result<(), terror::Error>> {
        let res = {
            let conn = self.state.inner.borrow_mut();
            conn.stream_finished(s_id)
        };

        if res {
            return Poll::Ready(Ok(()));
        }

        tracing::trace!("entering poll_finished");

        self.state
            .wakers
            .borrow_mut()
            .finished
            .insert(*s_id, cx.waker().clone());

        Poll::Pending
    }

    pub(crate) fn poll_send(
        &self,
        cx: &mut Context,
        s_id: &u64,
        buf: &[u8],
        fin: bool,
    ) -> Poll<Result<usize, terror::Error>> {
        let res = {
            let mut conn = self.state.inner.borrow_mut();
            conn.stream_write(*s_id, buf, fin)
        };

        self.state.mark_pending();
        match res {
            Ok(0) if !buf.is_empty() => {
                // local backpressure: buffer full
                self.state
                    .wakers
                    .borrow_mut()
                    .write
                    .insert(*s_id, cx.waker().clone());
                Poll::Pending
            }
            other => Poll::Ready(other),
        }
    }

    fn poll_accept(&self, cx: &mut Context, stream_t: u64) -> Poll<Result<u64, terror::Error>> {
        let mut conn = self.state.inner.borrow_mut();

        if conn.is_closing() || conn.is_closed() {
            if let Some(ec) = conn.apec {
                return Poll::Ready(Err(terror::Error::connection_closed(format!(
                    "connection closed with: {}",
                    ec
                ))));
            };
        }

        if let Some(id) = conn.stream_accept(stream_t) {
            tracing::debug!(cid = %self.state.internal_id, stream = id, kind = stream_t, "new stream accepted");
            return Poll::Ready(Ok(id));
        }

        let idx = (stream_t | ((self.state.side as u64) ^ 0x01)) as usize;
        let mut w = self.state.wakers.borrow_mut();
        match &w.streams[idx] {
            Some(existing) if !existing.will_wake(cx.waker()) => {
                return Poll::Ready(Err(terror::Error::concurrent_accept(
                    "two tasks awaiting the same stream type",
                )));
            }
            _ => w.streams[idx] = Some(cx.waker().clone()),
        }

        Poll::Pending
    }

    fn poll_open(&self, cx: &mut Context, stream_t: u64) -> Poll<Result<u64, terror::Error>> {
        let mut conn = self.state.inner.borrow_mut();

        if conn.is_closing() || conn.is_closed() {
            if let Some(ec) = conn.apec {
                return Poll::Ready(Err(terror::Error::connection_closed(format!(
                    "connection closed with: {}",
                    ec
                ))));
            };
        }

        if let Some(id) = conn.stream_open(stream_t) {
            tracing::debug!(cid = %self.state.internal_id, stream = id, kind = stream_t, "new stream opened");
            return Poll::Ready(Ok(id));
        }

        let idx = (stream_t | (self.state.side as u64)) as usize;
        self.state.wakers.borrow_mut().streams[idx] = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl Clone for Connection {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}
