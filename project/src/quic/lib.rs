mod packet;
pub mod terror;
mod token;
mod transport_parameters;

use octets::OctetsMut;
use packet::{
    AckFrame, ConnectionCloseFrame, CryptoFrame, Frame, Header, NewTokenFrame, StreamFrame,
};
use rand::RngCore;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    quic::{
        Connection as RustlsConnection, DirectionalKeys, KeyChange, Keys, PacketKeySet, Version,
    },
    Side,
};
use std::{
    collections::{HashMap, VecDeque},
    fmt,
    net::SocketAddr,
    sync::Arc,
};
use token::StatelessResetToken;
use tokio::{
    net::UdpSocket as TokioUdpSocket,
    sync::{mpsc, oneshot, RwLock},
    task::JoinHandle,
};
use tracing::{debug, debug_span, error, event, info, warn, Instrument, Level};
use transport_parameters::{
    InitialMaxData, InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote,
    InitialMaxStreamsBidi, InitialSourceConnectionId, MaxUdpPayloadSize,
    OriginalDestinationConnectionId, StatelessResetTokenTP, TransportConfig, VarInt,
};

const MAX_CID_SIZE: usize = 20;

const SPACE_ID_INITIAL: usize = 0x00;
const SPACE_ID_HANDSHAKE: usize = 0x01;
const SPACE_ID_DATA: usize = 0x02;

//Thread Safe Distributor
type TSDistributor = Arc<RwLock<Distributor>>;

pub struct Distributor {
    //server config for rustls. Will have to be updated to allow client side endpoint
    server_config: Option<Arc<rustls::ServerConfig>>,

    //RFC 2104, used to generate reset tokens from connection ids
    hmac_reset_key: ring::hmac::Key,

    //channels for each connection
    connection_send_handles: HashMap<ConnectionId, mpsc::Sender<packet::Datagram>>,

    //cancellation token. if activated all connections are shut down
    cancellation_token: tokio_util::sync::CancellationToken,
}

impl Distributor {
    fn new(key: ring::hmac::Key, server_cfg: Option<Arc<rustls::ServerConfig>>) -> Self {
        Self {
            server_config: server_cfg,
            hmac_reset_key: key,
            connection_send_handles: HashMap::new(),
            cancellation_token: tokio_util::sync::CancellationToken::new(),
        }
    }
}

pub struct Acceptor {
    //queue for initial packets
    rx: mpsc::Receiver<packet::InitialDatagram>,
}

impl Acceptor {
    async fn accept(&mut self) -> Option<Connection> {
        let (packet, remote, tsd, socket) = self.rx.recv().await.unwrap();

        let (connection, ready) = match Connection::early_connection((packet, remote), tsd, socket)
            .instrument(debug_span!("new connection"))
            .await
        {
            Ok((c, r)) => (c, r),
            Err(e) => {
                // if we encounter an error within the initial packet, the connection is
                // immediately abandoned
                // TODO send close connection frame, remove conn from Distributor
                error!("encountered error while accepting new connection: {}", e);
                return None;
            }
        };

        //send connection close frame
        match ready.await {
            Ok(terror::QuicTransportError::NoError) => return Some(connection),
            Ok(quic_error) => {
                error!("Connection could not be established: {}", quic_error);
            }
            Err(error) => {
                error!("Error retrieving connection state: {}", error);
            }
        }

        // force terminate connection recv task
        connection.abort();
        None
    }
}

pub struct Server {
    endpoint: Endpoint,
    acceptor: Acceptor,
}

impl Server {
    pub async fn accept(&mut self) -> Option<Connection> {
        self.acceptor.accept().await
    }

    pub async fn stop(&mut self) {
        self.endpoint
            .distributor
            .read()
            .await
            .cancellation_token
            .cancel();
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
                    panic!("failed to read certificate: {}", e);
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
        let mut endpoint = Endpoint::new(
            self.address.as_ref(),
            Some(Arc::new(
                self.server_config
                    .expect("server config should contain valid config"),
            )),
        )
        .await;

        let acceptor = endpoint.start_acceptor().await;

        Ok(Server { endpoint, acceptor })
    }
}

pub struct Endpoint {
    address: String,

    //task handles for recv and send loops
    recv_loop_handle: Option<JoinHandle<Result<u64, terror::Error>>>,

    //stores connection channel sender handles
    distributor: TSDistributor,
}

impl Endpoint {
    pub async fn new(addr: &str, server_config: Option<Arc<rustls::ServerConfig>>) -> Self {
        let mut hmac_reset_key = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut hmac_reset_key);

        let distributor = Arc::new(RwLock::new(Distributor::new(
            ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &hmac_reset_key),
            server_config,
        )));

        Endpoint {
            address: addr.to_string(),
            recv_loop_handle: None,
            distributor,
        }
    }

    pub async fn start_acceptor(&mut self) -> Acceptor {
        //socket lives via Arc in the recv loop and in each connection
        let socket = Arc::new(
            TokioUdpSocket::bind(self.address.clone())
                .await
                .expect("fatal error: socket bind failed"),
        );

        //TODO add to configuration of (server) endpoint maximum number of buffered inital packets
        let (tx_initial, rx_initial) = mpsc::channel::<packet::InitialDatagram>(64);
        let dist = self.distributor.clone();
        let cancellation_token = { dist.read().await.cancellation_token.clone() };

        info!("listening on {}", &self.address);

        self.recv_loop_handle = Some(tokio::spawn(async move {
            loop {
                let mut buffer = std::iter::repeat(0)
                    .take(u16::MAX as usize)
                    .collect::<Vec<_>>();

                let (size, src_addr) = match socket.recv_from(&mut buffer).await {
                    Ok((size, src_addr)) => (size, src_addr),
                    Err(error) => {
                        println!("Error while receiving datagram: {:?}", error);
                        continue;
                    }
                };

                let head = match &buffer[0] >> 7 {
                    0x01 => "LH",
                    0x00 => "SH",
                    _ => "NOT RECOGNISED",
                };

                info!("Received {:?} bytes from {:?} ({})", size, src_addr, head);
                //truncate vector to correct size
                buffer.truncate(size);

                let dcid = match Header::get_dcid(&buffer, 8) {
                    Ok(h) => h,
                    Err(error) => {
                        error!("error while retrieving dcid from packet: {}", error);
                        continue;
                    }
                };

                debug!("searching for {}", &dcid);

                //match incoming packet to connection
                if let Some(handle) = dist.read().await.connection_send_handles.get(&dcid) {
                    debug!("found existing connection");
                    handle.send((buffer, src_addr.to_string())).await.unwrap();
                } else {
                    //stop accepting new connections when entering graceful shutdown
                    if ((buffer[0] & packet::LS_TYPE_BIT) >> 7) == 1
                        && !cancellation_token.is_cancelled()
                    {
                        tx_initial
                            .send((
                                buffer,
                                src_addr.to_string(),
                                //partial_decode,
                                dist.clone(),
                                socket.clone(),
                            ))
                            .await
                            .unwrap();
                    }
                }

                if cancellation_token.is_cancelled() {
                    {
                        //return if all connections have been succesfully shut down
                        if dist.read().await.connection_send_handles.is_empty() {
                            return Ok(0);
                        }
                    }
                }
            }
        }));

        Acceptor { rx: rx_initial }
    }
}

pub struct Connection {
    //send socket
    socket: Arc<TokioUdpSocket>,

    //packet recv loop for connection
    loop_handle: Option<JoinHandle<Result<u64, terror::Error>>>,
    //stream acceptor handles
    //bidi_stream_r: mpsc::Receiver<stream::data>,
    //uni_stream_r: mpsc::Receiver<stream::data>,
}

impl Connection {
    //initializes a connection from an inital packet
    async fn early_connection(
        inital_datagram: packet::Datagram,
        tsd: TSDistributor,
        socket: Arc<TokioUdpSocket>,
    ) -> Result<(Self, oneshot::Receiver<terror::QuicTransportError>), terror::Error> {
        let (mut buffer, src_addr) = inital_datagram;
        let (hmac_reset_key, server_config) = {
            let t = tsd.read().await;
            (t.hmac_reset_key.clone(), t.server_config.clone())
        };

        let server_config = server_config.unwrap();

        let mut head = packet::Header::from_bytes(&buffer, 8).map_err(|e| {
            terror::Error::buffer_size_error(format!(
                "error decoding header from initial packet: {}",
                e
            ))
        })?;

        //get initial keys, use default crypto provider by ring with all suites for now
        let ikp = Connection::derive_initial_keyset(
            server_config.clone(),
            Version::V1,
            Side::Server,
            &head.dcid,
        );

        debug!(
            origin = src_addr,
            "initial keys ready for dcid {}", &head.dcid
        );

        let header_length = match head.decrypt(&mut buffer, ikp.remote.header.as_ref()) {
            Ok(s) => s,
            Err(error) => panic!("Error: {}", error),
        };

        let mut b = OctetsMut::with_slice(&mut buffer);
        let (header_raw, mut payload_cipher) = b.split_at(header_length).unwrap();

        //cut off trailing 0s from buffer, substract 1 extra beacuse packet num length of 1 is
        //encoded as 0...
        let (mut payload_cipher, _) = payload_cipher
            .split_at(head.length - head.packet_num_length as usize - 1)
            .unwrap();

        //payload cipher must be exact size without zeros from the buffer beeing to big!
        let dec_len = {
            let decrypted_payload_raw = match ikp.remote.packet.decrypt_in_place(
                head.packet_num.into(),
                header_raw.as_ref(),
                payload_cipher.as_mut(),
            ) {
                Ok(p) => p,
                Err(error) => {
                    return Err(terror::Error::crypto_error(format!(
                        "Error decrypting packet body {}",
                        error
                    )))
                }
            };
            decrypted_payload_raw.len()
        };

        //truncate payload to length returned by decrypting packet payload, may cause problems with
        //coalesced packets
        buffer.truncate(dec_len);

        let initial_local_scid = ConnectionId::generate_with_length(8);
        let orig_dcid = head.dcid.clone();

        let tpc = TransportConfig {
            original_destination_connection_id: OriginalDestinationConnectionId::try_from(
                orig_dcid.clone(),
            )?,
            initial_source_connection_id: InitialSourceConnectionId::try_from(
                initial_local_scid.clone(),
            )?,
            stateless_reset_token: StatelessResetTokenTP::try_from(
                token::StatelessResetToken::new(&hmac_reset_key, &initial_local_scid),
            )?,
            max_udp_payload_size: MaxUdpPayloadSize::try_from(VarInt::from(1472))?,
            initial_max_streams_bidi: InitialMaxStreamsBidi::try_from(VarInt::from(1))?,
            initial_max_data: InitialMaxData::try_from(VarInt::from(1024))?,
            initial_max_stream_data_bidi_remote: InitialMaxStreamDataBidiRemote::try_from(
                VarInt::from(1024),
            )?,
            initial_max_stream_data_bidi_local: InitialMaxStreamDataBidiLocal::try_from(
                VarInt::from(1024),
            )?,
            ..TransportConfig::default()
        };

        let data = tpc.encode(Side::Server)?;

        let conn = RustlsConnection::Server(
            rustls::quic::ServerConnection::new(server_config, rustls::quic::Version::V1, data)
                .unwrap(),
        );

        let initial_space: PacketNumberSpace = PacketNumberSpace {
            keys: Some(ikp),
            active: true,
            ..PacketNumberSpace::new()
        };

        let (transmit_q, recv_q) = mpsc::channel::<packet::Datagram>(8);

        {
            tsd.write()
                .await
                .connection_send_handles
                .insert(initial_local_scid.clone(), transmit_q);
        }

        debug!("inserted new recv handle for cid {}", initial_local_scid);

        let (conn_read_tx, conn_ready_rx) = oneshot::channel::<terror::QuicTransportError>();

        let cim = ConnectionIdManager::with_initial_cids(
            head.scid.clone().unwrap(),
            initial_local_scid,
            None,
            Some(orig_dcid),
        );

        let mut inner = Inner::new(
            Side::Server,
            head.version,
            conn,
            cim,
            src_addr.parse().unwrap(),
            initial_space,
            conn_read_tx,
        );

        let conn = Self {
            socket,
            loop_handle: None,
        };

        //process inital packet inside connection, all subsequent packets are sent through channel
        inner.accept(&head, &mut buffer)?;

        let mut buf = [0u8; 65536];

        let size = inner.fetch_dgram(&mut buf)?;
        conn.send(&buf[..size], inner.remote.to_string()).await?;

        //promote connection state
        inner.state = ConnectionState::Handshake;

        //start recv loop to process more incoming packets
        Ok((conn.start(recv_q, inner).await.unwrap(), conn_ready_rx))
    }

    fn derive_initial_keyset(
        server_cfg: Arc<rustls::ServerConfig>,
        version: Version,
        side: Side,
        dcid: &ConnectionId,
    ) -> Keys {
        /* for now only the rustls ring provider is used, so we may omit numerous checks */
        server_cfg
            .crypto_provider()
            .cipher_suites
            .iter()
            .find_map(|cs| match (cs.suite(), cs.tls13()) {
                (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(suite)) => {
                    Some(suite.quic_suite())
                }
                _ => None,
            })
            .flatten()
            .expect("default crypto provider failed to provide initial cipher suite")
            .keys(&dcid.id, side, version)
    }

    //starts recv_q, feeds into all other queues
    async fn start(
        mut self,
        mut recv_q: mpsc::Receiver<packet::Datagram>,
        mut conn: Inner,
    ) -> Result<Self, terror::Error> {
        let socket = self.socket.clone();

        self.loop_handle = Some(tokio::spawn(async move {
            while let Some(mut msg) = recv_q.recv().await {
                //process
                if let Err(error) = conn.recv(&mut msg) {
                    error!("error processing datagram: {}", error);
                };

                //prepare answer
                let mut buffer = [0u8; 65536];
                let size = match conn.fetch_dgram(&mut buffer) {
                    Ok(s) => s,
                    Err(err) => {
                        error!("failed to fetch datagram: {}", err);
                        continue;
                    }
                };

                //send data back
                let size = match socket.send_to(&buffer[..size], &msg.1).await {
                    Ok(size) => size,
                    Err(error) => {
                        return Err(terror::Error::socket_error(format!("{}", error)));
                    }
                };

                info!(destination = &msg.1, "sent {} bytes", size);
            }
            Ok(0)
        }));
        Ok(self)
    }

    async fn send(&self, dgram: &[u8], address: String) -> Result<(), terror::Error> {
        let size = match self.socket.send_to(dgram, &address).await {
            Ok(size) => size,
            Err(error) => {
                return Err(terror::Error::socket_error(format!("{}", error)));
            }
        };

        info!(destination = &address, "sent {} bytes", size);

        Ok(())
    }

    fn abort(self) {
        self.loop_handle.unwrap().abort();
    }

    //pub async fn accept_bidi_stream() {}

    //pub async fn accept_uni_stream() {}

    //pub async fn init_bidi_stream() {}

    //pub async fn init_uni_stream() {}
}

struct Inner {
    //oneshot channel
    conn_ready: oneshot::Sender<terror::QuicTransportError>,

    //side
    side: Side,

    //quic version
    version: u32,

    //tls13 session via rustls and keying material
    tls_session: RustlsConnection,
    next_secrets: Option<rustls::quic::Secrets>,
    next_1rtt_packet_keys: Option<PacketKeySet>,
    zero_rtt_keyset: Option<DirectionalKeys>,

    //connection state
    state: ConnectionState,

    //connection id manager
    cidm: ConnectionIdManager,

    // Packet number spaces, inital, handshake, 1-RTT
    packet_spaces: [PacketNumberSpace; 3],
    current_space: usize,

    // Physical address of connection peer
    remote: SocketAddr,

    // TransportConfig of remote
    remote_tpc: TransportConfig,

    //0-Rtt enabled
    zero_rtt_enabled: bool,
}

impl Inner {
    fn new(
        side: Side,
        version: u32,
        tls_session: RustlsConnection,
        cidm: ConnectionIdManager,
        remote_address: SocketAddr,
        initial_space: PacketNumberSpace,
        conn_ready: oneshot::Sender<terror::QuicTransportError>,
    ) -> Self {
        Self {
            conn_ready,
            side,
            version,
            tls_session,
            next_secrets: None,
            next_1rtt_packet_keys: None,
            zero_rtt_keyset: None,
            state: ConnectionState::Initial,
            cidm,
            packet_spaces: [
                initial_space,
                PacketNumberSpace::new(),
                PacketNumberSpace::new(),
            ],
            current_space: SPACE_ID_INITIAL,
            remote: remote_address,
            remote_tpc: TransportConfig::default(),
            zero_rtt_enabled: false,
        }
    }

    fn recv(&mut self, datagram: &mut packet::Datagram) -> Result<(), terror::Error> {
        let (buffer, _origin) = datagram;
        let mut offset: usize = 0;
        let mut remaining: usize = buffer.len();

        loop {
            let mut partial_decode = match packet::Header::from_bytes(&buffer[offset..], 8) {
                Ok(h) => h,
                Err(e) => {
                    if remaining == 0 {
                        return Ok(());
                    }

                    return Err(terror::Error::buffer_size_error(format!(
                        "error decoding packet header: {}",
                        e
                    )));
                }
            };

            let processed_bytes = self.recv_single(&mut buffer[offset..], &mut partial_decode)?;

            debug!(
                "processed packet with {} bytes. remaining: {}",
                processed_bytes,
                remaining - processed_bytes
            );

            offset += processed_bytes;
            remaining -= processed_bytes;
        }
    }

    #[tracing::instrument(skip_all, fields(space = header.space()))]
    fn recv_single(
        &mut self,
        packet: &mut [u8],
        header: &mut Header,
    ) -> Result<usize, terror::Error> {
        debug!("H: {}", header);

        //zero rtt
        if ((header.hf & packet::LS_TYPE_BIT) >> 7) == 0x01
            && ((header.hf & packet::LONG_PACKET_TYPE) >> 4) == 0x01
        {
            if !self.zero_rtt_enabled {
                return Err(terror::Error::quic_transport_error(
                    "received unexpected zero rtt packet",
                    terror::QuicTransportError::InternalError,
                ));
            }

            let _dk = self.zero_rtt_keyset.as_ref().unwrap();

            todo!("zero rtt packet handling is not yet implemented")
        }

        //retry
        if ((header.hf & packet::LS_TYPE_BIT) >> 7) == 0x01
            && ((header.hf & packet::LONG_PACKET_TYPE) >> 4) == 0x03
        {
            todo!("retry packet handling is not yet implemented")
        }

        //decrypt packet
        let keys: &DirectionalKeys = &self.packet_spaces[header.space()]
            .keys
            .as_ref()
            .unwrap()
            .remote;

        let header_length = match header.decrypt(packet, keys.header.as_ref()) {
            Ok(s) => s,
            Err(error) => {
                return Err(terror::Error::crypto_error(format!(
                    "unable to decrypt header: {}",
                    error
                )))
            }
        };

        let mut payload = OctetsMut::with_slice(packet);
        let (header_raw, mut rest) = payload.split_at(header_length)?;
        let mut payload_cipher: OctetsMut;

        //rfc 9000 sec 12.2: Retry packets, Version Negotiation packets, and packets with a
        //short header do not contain a Length field and so cannot be followed by other
        //packets in the same UDP datagram
        //Therefore we only need to trim payload_cipher if we have an initial, handshake or
        //zero rtt packet
        if header.space() == SPACE_ID_INITIAL
            || header.space() == SPACE_ID_HANDSHAKE
            || ((header.hf & packet::LS_TYPE_BIT) >> 7) == 0x01
                && ((header.hf & packet::LONG_PACKET_TYPE) >> 4) == 0x01
        {
            (payload_cipher, _) =
                rest.split_at(header.length - header.packet_num_length as usize - 1)?;
        } else {
            payload_cipher = rest;
        }

        let raw_packet_length = header_raw.len() + payload_cipher.len();

        //payload cipher must be exact size without zeros from the buffer beeing to big!
        let dec_len = {
            let decrypted_payload_raw = match keys.packet.decrypt_in_place(
                header.packet_num.into(),
                header_raw.as_ref(),
                payload_cipher.as_mut(),
            ) {
                Ok(p) => p,
                Err(error) => {
                    return Err(terror::Error::crypto_error(format!(
                        "unable to decrypt packet body {}",
                        error
                    )))
                }
            };
            decrypted_payload_raw.len()
        };

        let (mut payload, _) = payload_cipher.split_at(dec_len)?;

        self.process_payload(header, &mut payload)?;

        Ok(raw_packet_length)
    }

    //sends initial connection packet
    fn _connect(&mut self) -> Result<(), terror::Error> {
        Ok(())
    }

    //accepts new connection
    fn accept(&mut self, header: &Header, packet_raw: &mut [u8]) -> Result<(), terror::Error> {
        let mut payload = octets::OctetsMut::with_slice(packet_raw);

        //skip forth to packet payload
        payload.skip(header.raw_length + header.packet_num_length as usize + 1)?;

        self.process_payload(header, &mut payload)?;

        if let Some(tpc) = self.tls_session.quic_transport_parameters() {
            self.remote_tpc.update(tpc)?;
        }

        if self.remote_tpc.initial_source_connection_id.get().unwrap()
            != self.cidm.get_inital_remote_scid().unwrap()
        {
            return Err(terror::Error::quic_transport_error(
                "scids from packet header and transport parameters differ",
                terror::QuicTransportError::TransportParameterError,
            ));
        }

        self.generate_crypto_data(SPACE_ID_INITIAL);
        self.generate_crypto_data(SPACE_ID_HANDSHAKE);

        //init zero rtt if enabled
        if self.zero_rtt_enabled {
            if let Some(zero_rtt_keyset) = self.tls_session.zero_rtt_keys() {
                self.zero_rtt_keyset = Some(zero_rtt_keyset);
            } else {
                error!("failed to derive zero rtt keyset");
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip_all, fields(pn = header.packet_num))]
    fn process_payload(
        &mut self,
        header: &Header,
        payload: &mut OctetsMut,
    ) -> Result<(), terror::Error> {
        let mut ack_eliciting = false;

        while payload.peek_u8().is_ok() {
            let frame_code = payload.get_u8().unwrap();

            //check if frame is ack eliciting
            match frame_code {
                0x00 | 0x02 | 0x03 | 0x1c | 0x1d => (),
                _ => ack_eliciting = true,
            }

            match frame_code {
                0x00 => {
                    let _ = payload.get_u8();
                } //PADDING
                0x01 => {} //PING
                0x02 | 0x03 => {
                    let ack = AckFrame::from_bytes(&frame_code, payload);
                    self.process_ack(ack, header.space())?;
                } //ACK
                0x04 => {
                    let _stream_id = payload.get_varint().unwrap();
                    let _application_protocol_error_code = payload.get_varint().unwrap();
                    let _final_size = payload.get_varint().unwrap();
                } //RESET_STREAM
                0x05 => {
                    let _stream_id = payload.get_varint().unwrap();
                    let _application_protocol_error_code = payload.get_varint().unwrap();
                } //STOP_SENDING
                0x06 => {
                    let crypto_frame = CryptoFrame::from_bytes(&frame_code, payload);
                    self.process_crypto_data(&crypto_frame);

                    //test if all required crypto data has been exchanged for the connection to be
                    //considered established
                    if self.tls_session.alpn_protocol().is_some()
                        && self.tls_session.negotiated_cipher_suite().is_some()
                        && !self.tls_session.is_handshaking()
                        && self.state == ConnectionState::Handshake
                    {
                        event!(
                            Level::INFO,
                            "connection established to {}",
                            self.remote.to_string()
                        );

                        self.state = ConnectionState::Connected;
                        self.transmit_ready(terror::QuicTransportError::NoError);
                    }
                } //CRYPTO
                0x07 => {
                    if self.side != Side::Server {
                        let _new_token = NewTokenFrame::from_bytes(&frame_code, payload);
                    } else {
                        //Quic Error: ProtocolViolation
                    }
                } //NEW_TOKEN
                0x08..=0x0f => {
                    let stream_frame = StreamFrame::from_bytes(&frame_code, payload);
                    let (_, mut stream_data) = payload.split_at(payload.off()).unwrap();

                    //isolate stream data if offset is present, else data extends to end of packet
                    //TODO skip stream data
                    if stream_frame.offset.is_some() {
                        (stream_data, _) =
                            payload.split_at(stream_frame.offset.unwrap() as usize)?;
                    }
                    println!("STREAM DATA: {:x?}", stream_data);
                } //STREAM
                0x10 => {
                    let _max_data = payload.get_varint().unwrap();
                } //MAX_DATA
                0x11 => {
                    let _stream_id = payload.get_varint().unwrap();
                    let _max_data = payload.get_varint().unwrap();
                } //MAX_STREAM_DATA
                0x12 => {
                    let _maximum_streams = payload.get_varint().unwrap();
                } //MAX_STREAMS (bidirectional)
                0x13 => {
                    let _maximum_streams = payload.get_varint().unwrap();
                } //MAX_STREAMS (unidirectional)
                0x14 => {
                    let _maximum_data = payload.get_varint().unwrap();
                } //DATA_BLOCKED
                0x15 => {
                    let _stream_id = payload.get_varint().unwrap();
                    let _maximum_stream_data = payload.get_varint().unwrap();
                } //STREAM_DATA_BLOCKED
                0x16 => {
                    let _maximum_streams = payload.get_varint().unwrap();
                } //STREAMS_BLOCKED (bidirectional)
                0x17 => {
                    let _maximum_streams = payload.get_varint().unwrap();
                } //STREAMS_BLOCKED (unidirectional)
                0x18 => {
                    println!("NEW CID");
                    let sqn = payload.get_varint().unwrap();
                    let retire_prior_to = payload.get_varint().unwrap();
                    let l = payload.get_u8().unwrap();
                    let n_cid = ConnectionId::from(payload.get_bytes(l as usize).unwrap().to_vec());

                    if retire_prior_to > sqn {
                        return Err(terror::Error::quic_transport_error(
                            "retire prior to is greater than sequence number",
                            terror::QuicTransportError::FrameEncodingError,
                        ));
                    }

                    //dunno what to do
                    let _srt = StatelessResetToken::from(payload.get_bytes(0x10).unwrap().to_vec());

                    debug!(
                        "received new cid from peer: {} (sqn: {}, rpt: {})",
                        n_cid, sqn, retire_prior_to
                    );

                    self.cidm.register_new_cid(retire_prior_to, sqn, n_cid)?;
                } //NEW_CONNECTION_ID
                0x19 => {
                    let _sequence_number = payload.get_varint().unwrap();
                } //RETIRE_CONNECTION_ID
                0x1a => {
                    let _path_challenge_data = payload.get_u64().unwrap();
                } //PATH_CHALLENGE
                0x1b => {
                    let _path_response_data = payload.get_u64().unwrap();
                } //PATH_RESPONSE
                0x1c | 0x1d => {
                    let _connection_close = ConnectionCloseFrame::from_bytes(&frame_code, payload);
                } //CONNECTION_CLOSE_FRAME
                0x1e => {
                    if self.side == Side::Server {
                        error!("Received HANDSHAKE_DONE frame as server");
                        self.transmit_ready(terror::QuicTransportError::ProtocolViolation);
                        continue;
                    }

                    self.transmit_ready(terror::QuicTransportError::NoError);
                } // HANDSHAKE_DONE
                _ => warn!(
                    "Error while processing frames: unrecognised frame {:#x} at {:#x}",
                    frame_code,
                    payload.off()
                ),
            }
        }

        if ack_eliciting {
            self.packet_spaces[header.space()]
                .outgoing_acks
                .push(header.packet_num.into());
        }

        Ok(())
    }

    fn process_ack(&mut self, ack: AckFrame, space: usize) -> Result<(), terror::Error> {
        let acknowledged = ack.into_pn_vec();

        debug!(
            "got ack frame acknowledging the following packet numbers: {:?}",
            acknowledged
        );

        //both vecs are guaranteed to be sorted with no duplicate values
        //remove acknowledged pns from cached pns awaiting acknowledgement
        let to_remove = std::collections::BTreeSet::from_iter(acknowledged);
        self.packet_spaces[space]
            .awaiting_acknowledgement
            .retain(|e| !to_remove.contains(e));

        debug!(
            "{:?} are the packet numbers still awaiting acknowledgement",
            self.packet_spaces[space].awaiting_acknowledgement
        );

        Ok(())
    }

    fn transmit_ready(&mut self, error_code: terror::QuicTransportError) {
        let (tx, _) = oneshot::channel::<terror::QuicTransportError>();
        let ready = std::mem::replace(&mut self.conn_ready, tx);

        if let Err(err) = ready.send(error_code) {
            eprintln!("receiver of oneshot channel \"ready\" dropped {}", err);
        }
    }

    fn process_crypto_data(&mut self, crypto_frame: &CryptoFrame) {
        match self.tls_session.read_hs(crypto_frame.data()) {
            Ok(()) => debug!(
                "consumed {} bytes from crypto frame",
                crypto_frame.data().len()
            ),
            Err(err) => {
                error!("Error reading crypto data: {}", err);
                error!("{:?}", self.tls_session.alert().unwrap());
            }
        }

        let has_server_name = match self.tls_session {
            RustlsConnection::Client(_) => false,
            RustlsConnection::Server(ref session) => session.server_name().is_some(),
        };

        if self.tls_session.alpn_protocol().is_some()
            || has_server_name
            || !self.tls_session.is_handshaking()
        {
            let _ = true;
        }
    }

    fn generate_crypto_data(&mut self, space_id: usize) {
        let mut buf: Vec<u8> = Vec::new();

        //writing handshake data prompts a keychange because the packet number space is promoted
        if let Some(kc) = self.tls_session.write_hs(&mut buf) {
            debug!("generated {} bytes of crypto data", buf.len());
            //get keys from keychange
            let keys = match kc {
                KeyChange::Handshake { keys } => {
                    debug!("handshake keyset ready");
                    self.packet_spaces[SPACE_ID_HANDSHAKE].active = true;
                    keys
                }
                KeyChange::OneRtt { keys, next } => {
                    debug!("data (1-rtt) keyset ready");
                    self.next_secrets = Some(next);
                    self.packet_spaces[SPACE_ID_DATA].active = true;
                    keys
                }
            };

            // if space id is DATA, only the packet payload keys update, not the header keys
            if (space_id + 1) == SPACE_ID_DATA {
                self.next_1rtt_packet_keys = Some(
                    self.next_secrets
                        .as_mut()
                        .expect("handshake should be completed and next secrets availible")
                        .next_packet_keys(),
                )
            }

            //"upgrade" to next packet number space with new keying material
            self.packet_spaces[space_id + 1].keys = Some(keys);

            //advance space
            self.current_space = space_id + 1;
        };

        if buf.is_empty() && space_id == self.current_space {
            return;
        }

        println!("crypto data: {:x?}", buf);

        //create outgoing crypto frame
        let offset = self.packet_spaces[space_id].outgoing_crypto_offset;
        let length = buf.len() as u64;
        self.packet_spaces[space_id]
            .outgoing_crypto
            .push_back(packet::CryptoFrame::new(offset, buf));
        self.packet_spaces[space_id].outgoing_crypto_offset += length;
    }

    //TODO check errors on return: either no error, no_data error or other fatal error
    fn fetch_dgram(&mut self, buffer: &mut [u8]) -> Result<usize, terror::Error> {
        let availible = buffer.len();
        let max_payload_size = self.remote_tpc.max_udp_payload_size.get().unwrap().get();

        let mut remaining = std::cmp::min(availible, max_payload_size as usize);
        let mut written: usize = 0;

        let mut contains_initial = false;
        let mut encoded_packets: usize = 0;

        while remaining > 0 {
            let (packet_type, space_id) = self.get_packet_type();

            if packet_type == packet::PacketType::None {
                //either we're done or we need to throw an error
                if encoded_packets == 0 {
                    return Err(terror::Error::no_data("no data to send"));
                } else {
                    return Ok(written);
                }
            }

            debug!(
                "building packet type {} in space {} with remaining space of {}",
                packet_type, space_id, remaining
            );

            let pn = self.packet_spaces[space_id].get_next_pkt_num();
            let dcid = self.cidm.get_dcid().unwrap();

            let header = match packet_type {
                packet::PacketType::Short => {
                    //TODO find correct values for spin_bit and key_phase
                    packet::Header::new_short_header(0x00, 0x00, self.version, pn, dcid)
                }
                _ => {
                    let (token, long_header_type) = if packet_type == packet::PacketType::Initial {
                        contains_initial = true;
                        (Some(vec![0u8]), packet::LONG_HEADER_TYPE_INITIAL)
                    } else {
                        (None, packet::LONG_HEADER_TYPE_HANDSHAKE)
                    };

                    let scid = self.cidm.get_scid().unwrap();

                    packet::Header::new_long_header(
                        long_header_type,
                        self.version,
                        pn,
                        dcid,
                        scid,
                        token,
                        0,
                    )
                }
            }?;

            debug!("with header: {}", header);

            let keys = if let Some(crypto) = self.packet_spaces[space_id].keys.as_ref() {
                &crypto.local
            } else {
                return Err(terror::Error::crypto_error(format!(
                    "no availible keys in space {}",
                    space_id
                )));
            };

            let packet_size_overhead =
                header.raw_length + header.packet_num_length as usize + 1 + keys.packet.tag_len();

            debug!("packet_size_overhead: {}", packet_size_overhead);

            //check if size overhead for packet fits in rest
            if packet_size_overhead > remaining {
                //either we're done or we need to throw an error
                if encoded_packets == 0 {
                    return Err(terror::Error::buffer_size_error(format!(
                        "insufficient sized buffer for first packet: {}",
                        packet_size_overhead
                    )));
                } else {
                    return Ok(written);
                }
            }

            let mut buf = octets::OctetsMut::with_slice(&mut buffer[written..remaining]);

            //encode header and keep track of where the length field has been encoded
            let mut header_length_offset: usize = 0;
            header.to_bytes(&mut buf, &mut header_length_offset)?;

            //println!("after header encoding: {:x?}", &buf.buf()[..buf.off()]);

            let payload_offset = buf.off();

            debug!("payload_offset: {}", payload_offset);

            assert!(
                header.raw_length + header.packet_num_length as usize + 1 == buf.off(),
                "header end offset does not match"
            );

            //fill that packet with data
            //fetch acks
            if !self.packet_spaces[space_id].outgoing_acks.is_empty() {
                //sort outgoing acks in reverse to ease range building
                self.packet_spaces[space_id]
                    .outgoing_acks
                    .sort_by(|a, b| b.cmp(a));

                debug!(
                    "creating ack frame for pns {:?} in space {}",
                    self.packet_spaces[space_id].outgoing_acks, space_id
                );

                //TODO figure out delay
                let ack_delay = 64 * (2 ^ self.remote_tpc.ack_delay_exponent.get().unwrap().get());

                //directly generate ack frame from packet number vector
                let ack_frame = AckFrame::from_packet_number_vec(
                    &self.packet_spaces[space_id].outgoing_acks,
                    ack_delay,
                );

                //clear vector as packet numbers are now ack'ed
                self.packet_spaces[space_id].outgoing_acks.clear();

                if let Err(err) = packet::encode_frame(&ack_frame, &mut buf) {
                    return Err(terror::Error::buffer_size_error(format!(
                        "insufficient sized buffer for ack frame ({})",
                        err
                    )));
                };
            };

            //CRYPTO
            while let Some(frame) = self.packet_spaces[space_id].outgoing_crypto.pop_front() {
                if let Err(err) = packet::encode_frame(&frame, &mut buf) {
                    //no more space, put frame back
                    self.packet_spaces[space_id]
                        .outgoing_crypto
                        .push_front(frame);

                    return Err(terror::Error::buffer_size_error(format!(
                        "insufficient sized buffer for crypto frame ({})",
                        err
                    )));
                };
            }

            if packet_type == packet::PacketType::Short {
                //encode stream frames
            }

            //if is last packet, pad to min size of 1200
            if contains_initial
                && !self.packet_spaces[std::cmp::min(space_id + 1, SPACE_ID_DATA)].wants_write()
            {
                //if packet header is long, add padding length to length field, if it is short skip
                //padding length
                if (buf.off() + written) < 1200 {
                    let skip = std::cmp::min(1200 - buf.off() - written, 0);
                    debug!(
                        "datagram contains initial frame and this last packet is padded by: {}",
                        skip
                    );
                    buf.skip(skip)?;
                }
            }

            debug!(
                "offset after payload (incl. written): {}",
                buf.off() + written
            );

            let payload_length = buf.off() - payload_offset;
            debug!("payload length: {}", payload_length);

            let length =
                payload_length + keys.packet.tag_len() + (header.packet_num_length as usize + 1);

            //determine length of packet and encode it
            if packet_type != packet::PacketType::Short {
                debug!("encoded length in header: {}", length);

                let (_, mut l) = buf.split_at(header_length_offset)?;
                l.put_varint_with_len(length as u64, packet::PACKET_LENGTH_ENCODING_LENGTH)?;
            }

            //encrypt the packet
            let packet_length = packet::encrypt(&mut buf, keys, pn, payload_offset)?;

            debug!("packet_length: {}", packet_length);

            encoded_packets += 1;
            remaining -= packet_length;
            written += packet_length;

            //short packets cannot be coalesced
            if packet_type == packet::PacketType::Short {
                break;
            }
        }

        Ok(written)
    }

    fn get_packet_type(&self) -> (packet::PacketType, usize) {
        for space in SPACE_ID_INITIAL..=SPACE_ID_DATA {
            if self.packet_spaces[space].wants_write() {
                return (packet::PacketType::from(space), space);
            }
        }

        (packet::PacketType::None, 0)
    }
}

#[derive(PartialEq)]
enum ConnectionState {
    Initial,
    Handshake,
    Connected,
    Emtpying,
    Terminated,
}

//RFC 9000 section 12.3. we have 3 packet number spaces: initial, handshake & 1-RTT
struct PacketNumberSpace {
    keys: Option<Keys>,

    outgoing_acks: Vec<u64>,
    awaiting_acknowledgement: Vec<u64>,

    outgoing_crypto: VecDeque<packet::CryptoFrame>,
    outgoing_crypto_offset: u64,

    next_pkt_num: u32,

    active: bool,
}

impl PacketNumberSpace {
    fn new() -> Self {
        Self {
            keys: None,
            outgoing_acks: Vec::new(),
            awaiting_acknowledgement: Vec::new(),
            outgoing_crypto: VecDeque::new(),
            outgoing_crypto_offset: 0,
            next_pkt_num: 0,
            active: false,
        }
    }

    //determines if a space has outgoing crypto data or acks
    //TODO expand with lost packets
    fn wants_write(&self) -> bool {
        self.active && (!self.outgoing_acks.is_empty() || !self.outgoing_crypto.is_empty())
    }

    fn get_next_pkt_num(&mut self) -> u32 {
        self.next_pkt_num += 1;
        self.next_pkt_num - 1
    }

    // once a key replace is triggered, the next 1-rtt packet keys replace the old ones in the data
    // space. The next 1-rtt are then derived from the secret
    fn replace_packet_keys(&mut self, packet_keys: PacketKeySet) {
        //maybe save old keys to keep in case a keyupdate is not completed
        let _ = std::mem::replace(
            &mut self.keys.as_mut().unwrap().local.packet,
            packet_keys.local,
        );

        let _ = std::mem::replace(
            &mut self.keys.as_mut().unwrap().remote.packet,
            packet_keys.remote,
        );
    }
}

struct ConnectionIdManager {
    //index represents sequence number
    //set of cids maintained by peer via NEW_CONNECTION_ID frames. we retire them with
    //RETIRE_CONNECTION_ID frames
    dcids: Vec<ConnectionId>,

    //index represents sequence number
    //set of cids maintained by us which identify the connection on our side. we send
    //NEW_CONNECTION_ID frames to add cids. the peer retires them with RETIRE_CONNECTION_ID frames
    scids: Vec<ConnectionId>,

    //highest received "retire prior to"
    rpt_r: u64,

    //highest sent retire_prior_to
    rpt_s: u64,

    //sent by client
    retry_source_connection_id: Option<ConnectionId>,

    original_destination_connection_id: Option<ConnectionId>,
}

impl ConnectionIdManager {
    fn with_initial_cids(
        dcid: ConnectionId,
        scid: ConnectionId,
        retry_source_connection_id: Option<ConnectionId>,
        original_destination_connection_id: Option<ConnectionId>,
    ) -> Self {
        Self {
            dcids: vec![dcid],
            scids: vec![scid],
            rpt_r: 0,
            rpt_s: 0,
            retry_source_connection_id,
            original_destination_connection_id,
        }
    }

    //registeres a new cid from a NEW_CONNECTION_ID frame
    fn register_new_cid(
        &mut self,
        retire_prior_to: u64,
        sqn: u64,
        cid: ConnectionId,
    ) -> Result<(), terror::Error> {
        if sqn < self.rpt_r {
            //cid is immediately retired
            return Ok(());
        }

        self.rpt_r = std::cmp::max(self.rpt_r, retire_prior_to);

        let dcids_len = self.dcids.len() as u64;

        if dcids_len == sqn {
            self.dcids.push(cid);
            return Ok(());
        }

        if dcids_len > sqn {
            assert_eq!(cid, self.dcids[sqn as usize]);
        }

        if dcids_len < sqn {
            return Err(terror::Error::quic_transport_error(
                "sequence number is not one greater than previous one",
                terror::QuicTransportError::ProtocolViolation,
            ));
        }

        Ok(())
    }

    //create a new cid to be used in a NEW_CONNECTION_ID frame
    fn issue_new_cid(&mut self) {}

    fn get_inital_remote_scid(&self) -> Option<&ConnectionId> {
        self.dcids.first()
    }

    fn get_dcid(&self) -> Option<&ConnectionId> {
        Some(&self.dcids[self.rpt_r as usize])
    }

    fn get_scid(&self) -> Option<&ConnectionId> {
        self.scids.last()
    }
}

#[derive(Eq, Hash, PartialEq, Clone)]
pub struct ConnectionId {
    id: Vec<u8>,
}

impl ConnectionId {
    #[inline]
    pub const fn from_vec(cid: Vec<u8>) -> Self {
        Self { id: cid }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.id.len()
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.id
    }

    #[inline]
    pub fn id(&self) -> &Vec<u8> {
        &self.id
    }

    pub fn generate_with_length(length: usize) -> Self {
        assert!(length <= MAX_CID_SIZE);
        let mut b = [0u8; MAX_CID_SIZE];
        rand::thread_rng().fill_bytes(&mut b[..length]);
        ConnectionId::from_vec(b[..length].into())
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0x{}",
            self.id
                .iter()
                .map(|val| format!("{:x}", val))
                .collect::<Vec<String>>()
                .join("")
        )
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0x{}",
            self.id
                .iter()
                .map(|val| format!("{:x}", val))
                .collect::<Vec<String>>()
                .join("")
        )
    }
}

impl Default for ConnectionId {
    #[inline]
    fn default() -> Self {
        Self::from_vec(Vec::new())
    }
}

impl From<Vec<u8>> for ConnectionId {
    #[inline]
    fn from(v: Vec<u8>) -> Self {
        Self::from_vec(v)
    }
}
