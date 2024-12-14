mod io;
mod packet;
mod stream;
pub mod terror;
mod token;
mod transport_parameters;

use indexmap::IndexMap;
use octets::{varint_len, OctetsMut};
use packet::{AckFrame, ConnectionCloseFrame, Frame, Header};
use parking_lot::Mutex;
use rand::RngCore;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    quic::{
        Connection as RustlsConnection, DirectionalKeys, KeyChange, Keys, PacketKeySet, Version,
    },
    Side,
};
use std::{collections::VecDeque, fmt, future, net::SocketAddr, sync::Arc, task::Poll};
use stream::StreamManager;
use token::StatelessResetToken;
use tokio::sync::mpsc;
use tracing::{debug, error, event, span, warn, Level};
use transport_parameters::{
    InitialMaxData, InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote,
    InitialMaxStreamsBidi, InitialSourceConnectionId, MaxUdpPayloadSize,
    OriginalDestinationConnectionId, StatelessResetTokenTP, TransportConfig, VarInt,
};

const MAX_CID_SIZE: usize = 20;

const SPACE_ID_INITIAL: usize = 0x00;
const SPACE_ID_HANDSHAKE: usize = 0x01;
const SPACE_ID_DATA: usize = 0x02;

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

        io::start(endpoint, address).await?;

        Ok(Server {
            address,
            acceptor: Acceptor {
                rx: new_connection_rx,
            },
        })
    }
}

pub struct Endpoint {
    //owns the actual connection objects
    connections: IndexMap<ConnectionId, Arc<LockedInner>>,

    //server config for rustls. Will have to be updated to allow client side endpoint
    server_config: Option<Arc<rustls::ServerConfig>>,

    //RFC 2104, used to generate reset tokens from connection ids
    hmac_reset_key: ring::hmac::Key,

    //channels for initial and zero-rtt packets
    new_connection_tx: mpsc::Sender<Connection>,
}

pub struct LockedInner(Mutex<Inner>);

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
    api: Arc<dyn ConnectionApi>,
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

trait ConnectionApi: Send + Sync {
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

struct Inner {
    //side
    side: Side,

    //quic version
    version: u32,

    //pollable events
    events: Vec<InnerEvent>,

    //tls13 session via rustls and keying material
    tls_session: RustlsConnection,
    next_secrets: Option<rustls::quic::Secrets>,
    next_1rtt_packet_keys: Option<PacketKeySet>,
    zero_rtt_keyset: Option<DirectionalKeys>,

    //connection state
    state: ConnectionState,

    //connection id manager
    cidm: ConnectionIdManager,

    //stream manager, does all stream logic
    sm: StreamManager<stream::StreamWaker>,

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
    fn stream_accept(
        &mut self,
        stream_t: u64,
        wk: <stream::StreamWaker as stream::StreamCallback>::Callback,
    ) -> Option<u64> {
        let stream_t = stream_t & (self.side as u8) as u64;

        if let Some(id) = self.sm.poll_ready(stream_t, wk) {
            return Some(id);
        }

        None
    }

    fn stream_read(
        &mut self,
        stream_id: &u64,
        buf: &mut [u8],
        wk: <stream::StreamWaker as stream::StreamCallback>::Callback,
    ) -> Result<Option<usize>, terror::Error> {
        self.sm.consume(stream_id, buf, wk)
    }

    fn stream_write(
        &mut self,
        stream_id: u64,
        buf: &[u8],
        fin: bool,
    ) -> Result<usize, terror::Error> {
        self.sm.append(stream_id, buf, fin)
    }

    //creates a connection from an initial packet as a server. Takes the buffer, source address,
    //server config, hmac reset key and a oneshot channel which gets triggered as soon as the
    //connection is established. Returns the Connection itself and the initial source connection id which
    //is now used by the peer as dcid and from which the connection can now be identified.
    fn accept(
        buffer: &mut Vec<u8>,
        src_addr: String,
        server_config: Arc<rustls::ServerConfig>,
        hmac_reset_key: &ring::hmac::Key,
    ) -> Result<(Self, ConnectionId), terror::Error> {
        let mut head = packet::Header::from_bytes(buffer, 8).map_err(|e| {
            terror::Error::buffer_size_error(format!(
                "error decoding header from initial packet: {}",
                e
            ))
        })?;

        //get initial keys, use default crypto provider by ring with all suites for now
        let ikp = Inner::derive_initial_keyset(
            server_config.clone(),
            Version::V1,
            Side::Server,
            &head.dcid,
        );

        debug!(
            origin = src_addr,
            "initial keys ready for dcid {}", &head.dcid
        );

        let header_length = match head.decrypt(buffer, ikp.remote.header.as_ref()) {
            Ok(s) => s,
            Err(error) => panic!("Error: {}", error),
        };

        let mut b = OctetsMut::with_slice(buffer);
        let (header_raw, mut payload_cipher) = b.split_at(header_length).unwrap();

        //cut off trailing 0s from buffer, substract 1 extra beacuse packet num length of 1 is
        //encoded as 0...
        let (mut payload_cipher, _) = payload_cipher
            .split_at(head.length - head.packet_num_length as usize - 1)
            .unwrap();

        //payload cipher must be exact size without zeros from the buffer beeing to big!
        let dec_len = {
            let decrypted_payload_raw = match ikp.remote.packet.decrypt_in_place(
                head.packet_num,
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

        //truncate payload is possible because as a server the initial packet from a client cant be
        //coalesced
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
                token::StatelessResetToken::new(hmac_reset_key, &initial_local_scid),
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

        let cim = ConnectionIdManager::with_initial_cids(
            head.scid.clone().unwrap(),
            initial_local_scid.clone(),
            None,
            Some(orig_dcid),
        );

        let mut inner = Self {
            side: Side::Server,
            version: head.version,
            events: Vec::new(),
            tls_session: conn,
            next_secrets: None,
            next_1rtt_packet_keys: None,
            zero_rtt_keyset: None,
            state: ConnectionState::Initial,
            cidm: cim,
            sm: StreamManager::new(Side::Server as u8),
            packet_spaces: [
                initial_space,
                PacketNumberSpace::new(),
                PacketNumberSpace::new(),
            ],
            current_space: SPACE_ID_INITIAL,
            remote: src_addr.parse().unwrap(),
            remote_tpc: TransportConfig::default(),
            zero_rtt_enabled: false,
        };

        //process inital packet inside connection, all subsequent packets are sent through channel
        inner.process_initial_packet(&head, buffer)?;

        Ok((inner, initial_local_scid))
    }

    /*fn _connect(&mut self, buffer: &mut [u8], dst_addr: String) -> Result<Self, terror::Error> {
        Ok(())
    }*/

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

    fn recv(&mut self, buffer: &mut [u8], _origin: SocketAddr) -> Result<(), terror::Error> {
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
                header.packet_num,
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

    //accepts new connection
    fn process_initial_packet(
        &mut self,
        header: &Header,
        packet_raw: &mut [u8],
    ) -> Result<(), terror::Error> {
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

    //processes a packets payload. Takes the header of the packet and an OctetsMut object of the
    //payload starting after the packet number and ending with the last byte of this packets
    //payload. It must not include another packets header or payload.
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
                    //the first received padding indicates that the rest of the packet is also
                    //padded and can therefore be skipped
                    payload.skip(payload.cap())?;
                    break;
                } //PADDING
                0x01 => {} //PING
                0x02 | 0x03 => {
                    let ack = AckFrame::from_bytes(&frame_code, payload);
                    self.process_ack(ack, header.space())?;
                } //ACK
                0x04 => {
                    let stream_id = payload.get_varint()?;
                    let apec = payload.get_varint()?;
                    let final_size = payload.get_varint()?;

                    self.sm.reset(stream_id, apec, Some(final_size))?;
                } //RESET_STREAM
                0x05 => {
                    let _stream_id = payload.get_varint()?;
                    let _application_protocol_error_code = payload.get_varint()?;
                } //STOP_SENDING
                0x06 => {
                    let _offset = payload.get_varint()?;
                    let crypto_data = payload.get_bytes_with_varint_length()?.to_vec();

                    self.process_crypto_data(&crypto_data);

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
                        self.events.push(InnerEvent::ConnectionEstablished);
                    }
                } //CRYPTO
                0x07 => {
                    if self.side != Side::Server {
                        //let _new_token = NewTokenFrame::from_bytes(&frame_code, payload);
                    } else {
                        //Quic Error: ProtocolViolation
                    }
                } //NEW_TOKEN
                0x08..=0x0f => {
                    let stream_id = payload.get_varint()?;
                    let mut offset: u64 = 0;
                    let mut fin_bit_set = false;

                    if (frame_code & 0x04) != 0 {
                        offset = payload.get_varint()?;
                    }

                    let mut length: u64 = payload.cap() as u64;
                    if (frame_code & 0x02) != 0 {
                        length = payload.get_varint()?;
                    }

                    if (frame_code & 0x01) != 0 {
                        fin_bit_set = true;
                    }

                    let stream_data = payload.get_bytes(length as usize)?;

                    self.sm
                        .incoming(stream_id, offset, length, fin_bit_set, stream_data.buf())?;
                } //STREAM
                0x10 => {
                    let _max_data = payload.get_varint()?;
                } //MAX_DATA
                0x11 => {
                    let _stream_id = payload.get_varint()?;
                    let _max_data = payload.get_varint()?;
                } //MAX_STREAM_DATA
                0x12 => {
                    let _maximum_streams = payload.get_varint()?;
                } //MAX_STREAMS (bidirectional)
                0x13 => {
                    let _maximum_streams = payload.get_varint()?;
                } //MAX_STREAMS (unidirectional)
                0x14 => {
                    let _maximum_data = payload.get_varint()?;
                } //DATA_BLOCKED
                0x15 => {
                    let _stream_id = payload.get_varint()?;
                    let _maximum_stream_data = payload.get_varint()?;
                } //STREAM_DATA_BLOCKED
                0x16 => {
                    let _maximum_streams = payload.get_varint()?;
                } //STREAMS_BLOCKED (bidirectional)
                0x17 => {
                    let _maximum_streams = payload.get_varint()?;
                } //STREAMS_BLOCKED (unidirectional)
                0x18 => {
                    let sqn = payload.get_varint().unwrap();
                    let retire_prior_to = payload.get_varint()?;
                    let l = payload.get_u8().unwrap();
                    let n_cid = ConnectionId::from(payload.get_bytes(l as usize)?.to_vec());

                    if retire_prior_to > sqn {
                        return Err(terror::Error::quic_transport_error(
                            "retire prior to is greater than sequence number",
                            terror::QuicTransportError::FrameEncodingError,
                        ));
                    }

                    //dunno what to do
                    let _srt = StatelessResetToken::from(payload.get_bytes(0x10)?.to_vec());

                    debug!(
                        "received new cid from peer: {} (sqn: {}, rpt: {})",
                        n_cid, sqn, retire_prior_to
                    );

                    self.cidm
                        .register_new_cid(retire_prior_to, sqn, n_cid.clone())?;
                    self.events.push(InnerEvent::NewConnectionId(n_cid));
                } //NEW_CONNECTION_ID
                0x19 => {
                    let _sequence_number = payload.get_varint()?;
                } //RETIRE_CONNECTION_ID
                0x1a => {
                    let _path_challenge_data = payload.get_u64()?;
                } //PATH_CHALLENGE
                0x1b => {
                    let _path_response_data = payload.get_u64()?;
                } //PATH_RESPONSE
                0x1c | 0x1d => {
                    let _connection_close = ConnectionCloseFrame::from_bytes(&frame_code, payload);
                } //CONNECTION_CLOSE_FRAME
                0x1e => {
                    if self.side == Side::Server {
                        error!("Received HANDSHAKE_DONE frame as server");
                        continue;
                    }
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
                .push(header.packet_num);
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

    fn process_crypto_data(&mut self, crypto_data: &[u8]) {
        match self.tls_session.read_hs(crypto_data) {
            Ok(()) => debug!("consumed {} bytes from crypto frame", crypto_data.len()),
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
            .push_back((offset, buf));
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

            let span = span!(
                Level::DEBUG,
                "fetch_dgram",
                space = space_id,
                pn = tracing::field::Empty
            )
            .entered();

            if packet_type == packet::PacketType::None {
                //either we're done or we need to throw an error
                if encoded_packets == 0 {
                    return Err(terror::Error::no_data("no data to send"));
                } else {
                    return Ok(written);
                }
            }

            debug!("building {} packet", packet_type);
            debug!("remaining space {}", remaining);

            let pn = self.packet_spaces[space_id].get_next_pkt_num();
            let dcid = self.cidm.get_dcid().unwrap();

            span.record("pn", pn);

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

            debug!("Header: {}", header);

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

            //debug!("payload_offset: {}", payload_offset);

            assert!(
                header.raw_length + header.packet_num_length as usize + 1 == buf.off(),
                "header end offset does not match"
            );

            //fill that packet with data
            //ack frames
            if !self.packet_spaces[space_id].outgoing_acks.is_empty() {
                //sort outgoing acks in reverse to ease range building
                self.packet_spaces[space_id]
                    .outgoing_acks
                    .sort_by(|a, b| b.cmp(a));

                debug!(
                    "ACK frame: {:?}",
                    self.packet_spaces[space_id].outgoing_acks,
                );

                //TODO figure out delay
                let ack_delay = 64 * (2 ^ self.remote_tpc.ack_delay_exponent.get().unwrap().get());

                //directly generate ack frame from packet number vector
                let ack_frame = AckFrame::from_packet_number_vec(
                    &self.packet_spaces[space_id].outgoing_acks,
                    ack_delay,
                );

                if let Err(err) = packet::encode_frame(&ack_frame, &mut buf) {
                    return Err(terror::Error::buffer_size_error(format!(
                        "insufficient sized buffer for ack frame ({})",
                        err
                    )));
                };

                //clear vector as packet numbers are now ack'ed
                self.packet_spaces[space_id].outgoing_acks.clear();
            };

            //crypto frames
            while let Some((off, data)) = self.packet_spaces[space_id].outgoing_crypto.front() {
                let enc_len = 1 + varint_len(*off) + varint_len(data.len() as u64) + data.len();

                if buf.cap() >= enc_len {
                    debug!("CRYPTO frame: off {} len {}", off, data.len());

                    buf.put_u8(0x06)?;
                    buf.put_varint(*off)?;
                    buf.put_varint(data.len() as u64)?;
                    buf.put_bytes(data)?;

                    self.packet_spaces[space_id].outgoing_crypto.pop_front();
                } else {
                    warn!("not enough space left to encode crypto frame with len {enc_len}");
                }
            }

            //stream frames
            if packet_type == packet::PacketType::Short {
                let sframe_len = self.sm.emit_fill(buf.as_mut(), pn)?;
                buf.skip(sframe_len)?;
            }

            //if is last packet, pad to min size of 1200
            if contains_initial
                && !self.packet_spaces[std::cmp::min(space_id + 1, SPACE_ID_DATA)].wants_write()
            {
                //if packet header is long, add padding length to length field, if it is short skip
                //padding length
                if (buf.off() + written) < 1200 {
                    let skip = std::cmp::max(1200 - buf.off() - written, 0);
                    debug!(
                        "datagram contains initial frame and this last packet is padded by: {}",
                        skip
                    );
                    buf.skip(skip)?;
                }
            }

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

    pub fn poll_event(&mut self) -> Option<InnerEvent> {
        self.events.pop()
    }
}

enum InnerEvent {
    ConnectionEstablished,
    NewConnectionId(ConnectionId),
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

    outgoing_crypto: VecDeque<(u64, Vec<u8>)>,
    outgoing_crypto_offset: u64,

    next_pkt_num: u64,

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

    fn get_next_pkt_num(&mut self) -> u64 {
        self.next_pkt_num += 1;
        self.next_pkt_num - 1
    }

    // once a key replace is triggered, the next 1-rtt packet keys replace the old ones in the data
    // space. The next 1-rtt are then derived from the secret
    fn _replace_packet_keys(&mut self, packet_keys: PacketKeySet) {
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
    fn _issue_new_cid(&mut self) {}

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
