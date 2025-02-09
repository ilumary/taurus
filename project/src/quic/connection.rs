use indexmap::IndexMap;
use parking_lot::Mutex;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::debug;

use std::{future, net::SocketAddr, sync::Arc, task::Poll};

use crate::{io, stream, terror, ConnectionId, Inner};

// client impl

pub struct Connector {
    rx: mpsc::Receiver<Connection>,
}

impl Connector {
    async fn connect(&mut self) -> Option<Connection> {
        self.rx.recv().await
    }
}

pub struct Client {
    connector: Connector,
    socket: Arc<UdpSocket>,
}

impl Client {
    pub async fn connect(&mut self, to: SocketAddr) -> Option<Connection> {
        // let mut initial = [0u8; 1200];
        // let _ = Inner::connect(to, out_buf);
        // self.sock.send_to(to, out_buf);
        self.connector.connect().await
    }
}

pub struct ClientConfig {
    client_config: rustls::ClientConfig,
    listen_on: String,
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
            listen_on: "[::1]:4433".to_string(),
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
        self.listen_on = addr.to_string();
        self
    }

    pub async fn build(self) -> Result<Client, terror::Error> {
        let (new_connection_tx, new_connection_rx) = mpsc::channel::<Connection>(64);
        let hmac_reset_key = [0u8; 64];

        let endpoint = Endpoint {
            connections: IndexMap::<ConnectionId, Arc<LockedInner>>::new(),
            server_config: None,
            hmac_reset_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &hmac_reset_key),
            new_connection_tx,
        };

        let socket = Arc::new(
            UdpSocket::bind(self.listen_on)
                .await
                .expect("fatal error: socket bind failed"),
        );

        Ok(Client {
            socket: socket.clone(),
            connector: Connector {
                rx: new_connection_rx,
            },
        })
    }
}

// server impl

pub struct Acceptor {
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
    pub async fn accept(&mut self) -> Option<Connection> {
        self.acceptor.accept().await
    }
}

pub struct ServerConfig {
    server_config: Option<rustls::ServerConfig>,
    address: String,
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
            server_config: Some(server_cfg),
            address: addr.to_string(),
        }
    }

    pub fn with_supported_protocols(mut self, protocols: Vec<String>) -> Self {
        if let Some(ref mut sc) = &mut self.server_config {
            sc.alpn_protocols = protocols.into_iter().map(|p| p.into_bytes()).collect();
        }
        self
    }

    pub async fn build(self) -> Result<Server, terror::Error> {
        let (new_connection_tx, new_connection_rx) = mpsc::channel::<Connection>(64);
        let hmac_reset_key = [0u8; 64];
        let address = self.address.parse().unwrap();

        let endpoint = Endpoint {
            connections: IndexMap::<ConnectionId, Arc<LockedInner>>::new(),
            server_config: Some(Arc::new(
                self.server_config
                    .expect("server config should contain valid config"),
            )),
            hmac_reset_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &hmac_reset_key),
            new_connection_tx,
        };

        //io::start(endpoint, address).await?;

        Ok(Server {
            address,
            acceptor: Acceptor {
                rx: new_connection_rx,
            },
        })
    }
}

pub struct Endpoint {
    // owns the actual connection objects
    connections: IndexMap<ConnectionId, Arc<LockedInner>>,

    // server config for rustls. Will have to be updated to allow client side endpoint
    server_config: Option<Arc<rustls::ServerConfig>>,

    // RFC 2104, used to generate reset tokens from connection ids
    hmac_reset_key: ring::hmac::Key,

    // channel for sending new connections
    new_connection_tx: mpsc::Sender<Connection>,
}

impl Endpoint {
    pub fn recv(&self, recv_ref: thingbuf::mpsc::RecvRef<'_, (Vec<u8>, std::net::SocketAddr)>) {}

    pub fn transmit(&self, send_ref: thingbuf::mpsc::SendRef<'_, (Vec<u8>, std::net::SocketAddr)>) {
    }

    pub fn poll_wakeups(&self) -> std::task::Poll<Result<(), terror::Error>> {
        std::task::Poll::Pending
    }
}

pub struct LockedInner(Mutex<Inner>);

impl LockedInner {
    pub fn lock(&self) -> parking_lot::lock_api::MutexGuard<'_, parking_lot::RawMutex, Inner> {
        self.0.lock()
    }
}

impl ConnectionApi for LockedInner {
    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        s_id: &u64,
        buf: &mut [u8],
    ) -> Poll<Result<Option<usize>, terror::Error>> {
        let mut conn = self.0.lock();
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
        let mut conn = self.0.lock();
        Poll::Ready(conn.stream_write(*s_id, buf, fin))
    }

    fn poll_accept(
        &self,
        cx: &mut std::task::Context,
        stream_t: u64,
        arc: Connection,
    ) -> Poll<Result<(Option<stream::RecvStream>, Option<stream::SendStream>), terror::Error>> {
        let mut conn = self.0.lock();

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

    fn close(
        &self,
        _cx: &mut std::task::Context,
        _reason: &str,
    ) -> Poll<Result<(), terror::Error>> {
        Poll::Pending
    }

    fn application_protocol(&self) -> Option<String> {
        if let Some(alp) = self.0.lock().tls_session.alpn_protocol() {
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
    pub api: Arc<dyn ConnectionApi>,
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

    pub async fn close(&self, reason: &str) -> Result<(), terror::Error> {
        future::poll_fn(|cx| self.api.close(cx, reason)).await
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

pub trait ConnectionApi: Send + Sync {
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

    fn close(&self, cx: &mut std::task::Context, reason: &str) -> Poll<Result<(), terror::Error>>;

    fn application_protocol(&self) -> Option<String>;

    fn keep_alive(&self, enable: bool);

    fn zero_rtt(&self, enable: bool);
}
