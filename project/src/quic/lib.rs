mod packet;
pub mod quic_error;
mod stream;
mod token;
mod transport_parameters;

use octets::OctetsMut;
use packet::{
    AckFrame, ConnectionCloseFrame, CryptoFrame, Frame, Header, NewConnectionIdFrame,
    NewTokenFrame, StreamFrame,
};
use rand::RngCore;
use rustls::{
    quic::{Connection as RustlsConnection, KeyChange, Keys, PacketKeySet, Version},
    Side,
};
use std::{
    collections::HashMap,
    fmt,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
};
use tokio::{net::UdpSocket as TokioUdpSocket, sync::mpsc, task::JoinHandle};

const MAX_CID_SIZE: usize = 20;

const SPACE_ID_INITIAL: usize = 0x00;
const SPACE_ID_HANDSHAKE: usize = 0x01;
const SPACE_ID_DATA: usize = 0x02;

type Handle = usize;

pub enum Event {
    NewConnection(Handle),
    Handshaking(Handle),
    ConnectionEstablished(Handle),
    DataExchange(Handle),
    ConnectionClosed(Handle),
}

pub struct Acceptor {
    //queue for initial packets
    rx: mpsc::Receiver<(Vec<u8>, String, Header)>,
}

impl Acceptor {
    pub async fn accept(&mut self) -> Option<Connection> {
        let (packet, remote, header) = self.rx.recv().await.unwrap();
        println!("accepting connection from {:?}", &remote);
        header.debug_print();

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
}

pub struct ServerConfig {
    server_config: Option<rustls::ServerConfig>,
    address: String,
}

impl ServerConfig {
    pub fn local_server(addr: &str) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = rustls::PrivateKey(cert.serialize_private_key_der());
        let cert = rustls::Certificate(cert.serialize_der().unwrap());

        Self::new(addr, cert, key)
    }

    pub fn new(addr: &str, certificate: rustls::Certificate, pkey: rustls::PrivateKey) -> Self {
        let mut server_cfg = rustls::ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], pkey)
            .unwrap();
        server_cfg.max_early_data_size = u32::MAX;
        server_cfg.alpn_protocols = vec!["hq-29".into()];

        ServerConfig {
            server_config: Some(server_cfg),
            address: addr.to_string(),
        }
    }

    pub async fn build(self) -> Result<Server, quic_error::Error> {
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
    socket: Arc<TokioUdpSocket>,

    //task handles for recv and send loops
    recv_loop_handle: Option<JoinHandle<Result<u64, quic_error::Error>>>,
    send_loop_handle: Option<JoinHandle<Result<u64, quic_error::Error>>>,

    //channel handle for sending packages, tuple of buffer and address
    tx: Option<mpsc::Sender<(Vec<u8>, String)>>,

    //server config for rustls. Will have to be updated to allow client side endpoint
    server_config: Option<Arc<rustls::ServerConfig>>,
    //RFC 2104, used to generate reset tokens from connection ids
    hmac_reset_key: ring::hmac::Key,

    //stores connection handles
    conn_db: HashMap<ConnectionId, Handle>,
    connections: Vec<Connection>,
}

impl Endpoint {
    pub async fn new(addr: &str, server_config: Option<Arc<rustls::ServerConfig>>) -> Self {
        let mut hmac_reset_key = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut hmac_reset_key);

        Endpoint {
            socket: Arc::new(
                TokioUdpSocket::bind(addr)
                    .await
                    .expect("fatal error: socket bind failed"),
            ),
            recv_loop_handle: None,
            send_loop_handle: None,
            tx: None,
            server_config,
            hmac_reset_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &hmac_reset_key),
            conn_db: HashMap::new(),
            connections: Vec::new(),
        }
    }

    pub async fn start_acceptor(&mut self) -> Acceptor {
        //TODO add to configuration of (server) endpoint maximum number of buffered inital packets
        let (tx_initial, mut rx_initial) = mpsc::channel::<(Vec<u8>, String, Header)>(64);
        let recv_socket = self.socket.clone();

        self.recv_loop_handle = Some(tokio::spawn(async move {
            loop {
                let mut buffer = std::iter::repeat(0)
                    .take(u16::MAX as usize)
                    .collect::<Vec<_>>();

                let (size, src_addr) = match recv_socket.recv_from(&mut buffer).await {
                    Ok((size, src_addr)) => (size, src_addr),
                    Err(error) => {
                        println!("Error while receiving datagram: {:?}", error);
                        continue;
                    }
                };
                println!("Received {:?} bytes from {:?}", size, src_addr);
                let mut octets = OctetsMut::with_slice(&mut buffer[..size]);
                let partial_decode = Header::from_bytes(&mut octets, 8).unwrap();

                //TODO expand to non initial packets
                tx_initial
                    .send((buffer, src_addr.to_string(), partial_decode))
                    .await
                    .unwrap();

                //maybe implement sorting where only initial packets are presorted and all others
                //are forwarded to another task which only sorts them to their respective
                //connections
            }
        }));

        let send_socket = self.socket.clone();
        let (tx, mut rx) = mpsc::channel::<(Vec<u8>, String)>(64);
        self.tx = Some(tx);

        self.send_loop_handle = Some(tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let size = match send_socket.send_to(&msg.0, &msg.1).await {
                    Ok(size) => size,
                    Err(error) => {
                        return Err(quic_error::Error::socket_error(format!("{}", error)));
                    }
                };
                println!("sent {} bytes to {}", size, &msg.1);
            }
            Ok(0)
        }));

        Acceptor { rx: rx_initial }
    }

    // handles a single incoming UDP datagram
    pub fn recv(&mut self) -> Result<Event, quic_error::Error> {
        // TODO: handle coalescing inital, 0-rtt and handshake packets, max udp packet size is 65kb
        let mut buffer = [0u8; 65535];

        let (size, src_addr) = (0, "0.0.0.0:8080".parse::<SocketAddr>().unwrap());
        /*match self.socket.recv_from(&mut buffer) {
            Ok((size, src_addr)) => (size, src_addr),
            Err(error) => {
                println!("Error while receiving datagram: {:?}", error);
                return Err(quic_error::Error::socket_error("receiving packet"));
            }
        };*/
        println!("Received {:?} bytes from {:?}", size, src_addr);

        let mut octet_buffer = OctetsMut::with_slice(&mut buffer);

        //println!("\nRAW\n{:x?}", octet_buffer); // offset 0

        //check if most significant bit is 1 or 0, if 0 => short packet => have to get cid len
        //somehow
        let mut head: Header = match Header::from_bytes(&mut octet_buffer, 8) {
            Ok(h) => h,
            Err(error) => panic!("Error: {}", error),
        };

        //match connection if one already exists
        if let Some(h) = self.get_connection_handle(
            &head.dcid,
            &src_addr,
            ((head.hf & packet::LS_TYPE_BIT) >> 7) != 0,
        ) {
            //connection exists, pass packet to connection
            println!("Found existing connection for {}", &head.dcid);
            return match self
                .connections
                .get_mut(h)
                .unwrap()
                .recv(&mut head, &mut octet_buffer)
            {
                Ok(()) => Ok(Event::DataExchange(h)),
                Err(error) => Err(error),
            };
        }

        //handle new connection

        //get initial keys
        let ikp = Keys::initial(Version::V1, &head.dcid.id, Side::Server);

        match head.decrypt(&mut octet_buffer, &ikp.remote.header) {
            Ok(_) => {
                head.debug_print();
            }
            Err(error) => panic!("Error: {}", error),
        }

        let (header_raw, mut payload_cipher) = octet_buffer.split_at(octet_buffer.off()).unwrap();

        //cut off trailing 0s from buffer, substract 1 extra beacuse packet num length of 1 is
        //encoded as 0...
        let (mut payload_cipher, _) = payload_cipher
            .split_at(head.packet_length - head.packet_num_length as usize - 1)
            .unwrap();

        //payload cipher must be exact size without zeros from the buffer beeing to big!
        let dec_len = {
            let decrypted_payload_raw = match ikp.remote.packet.decrypt_in_place(
                head.packet_num.into(),
                header_raw.as_ref(),
                payload_cipher.as_mut(),
            ) {
                Ok(p) => p,
                Err(error) => panic!("Error decrypting packet body {}", error),
            };
            decrypted_payload_raw.len()
        };

        //truncate payload to length returned by decrypting packet payload
        let mut payload = OctetsMut::with_slice(payload_cipher.as_mut()[..dec_len].as_mut());

        let initial_local_scid = ConnectionId::generate_with_length(head.dcid.len());
        let orig_dcid = head.dcid.clone();

        let mut transport_config = transport_parameters::TransportConfig::default();
        transport_config
            .original_destination_connection_id(orig_dcid.id())
            .initial_source_connection_id(initial_local_scid.id())
            .stateless_reset_token(
                token::StatelessResetToken::new(&self.hmac_reset_key, &initial_local_scid)
                    .token
                    .to_vec(),
            );

        //Allocate byte buffer and encode transport config to create rustls connection
        let mut buf = [0u8; 1024];
        let mut param_buffer = OctetsMut::with_slice(&mut buf);
        transport_config.encode(&mut param_buffer).unwrap();
        let (data, _) = param_buffer.split_at(param_buffer.off()).unwrap();

        let conn = RustlsConnection::Server(
            rustls::quic::ServerConnection::new(
                self.server_config.as_ref().unwrap().clone(),
                rustls::quic::Version::V1,
                data.to_vec(),
            )
            .unwrap(),
        );

        let initial_space: PacketNumberSpace = PacketNumberSpace {
            keys: Some(Keys::initial(Version::V1, &head.dcid.id, Side::Server)),
            ..PacketNumberSpace::new(true)
        };

        let new_ch = 1; /*self
                        .create_connection(
                            Side::Server,
                            head.version,
                            orig_dcid,
                            head.scid.clone().unwrap(),
                            initial_local_scid,
                            conn,
                            ikp,
                            initial_space,
                            src_addr,
                        )
                        .unwrap();*/

        //accept new connection
        match self
            .connections
            .get_mut(new_ch)
            .unwrap()
            .accept(&head, &mut payload)
        {
            Ok(()) => Ok(Event::NewConnection(new_ch)), //return new connection event
            Err(error) => panic!("Error processing packet: {}", error),
        }
    }

    fn get_connection_handle(
        &self,
        dcid: &ConnectionId,
        _remote: &SocketAddr,
        _is_inital_or_0rtt: bool,
    ) -> Option<Handle> {
        //TODO check for inital dcids, only remote for cid-less connections
        if dcid.len() != 0 {
            if let Some(c) = self.conn_db.get(dcid) {
                return Some(*c);
            }
        }
        None
    }

    fn create_connection(
        &mut self,
        side: Side,
        version: u32,
        inital_dcid: ConnectionId,
        inital_scid: ConnectionId,
        inital_loc_scid: ConnectionId,
        tls_session: RustlsConnection,
        inital_keyset: Keys,
        initial_space: PacketNumberSpace,
        remote: SocketAddr,
    ) -> Result<Handle, quic_error::Error> {
        //generate new handle
        let new_connection_handle = self.connections.len();
        if let Some(v) = self
            .conn_db
            .insert(inital_dcid.clone(), new_connection_handle)
        {
            panic!(
                "Error: extremly unlikely event of identical cid {} from two different hosts",
                v
            )
        }

        self.connections.push(Connection::new(
            side,
            version,
            tls_session,
            inital_keyset,
            inital_dcid,
            inital_scid,
            inital_loc_scid,
            remote,
            initial_space,
        ));

        Ok(new_connection_handle)
    }

    //terminate all connections
    pub fn _close_endpoint() {}

    pub fn handle_connection(
        &mut self,
        connection_handle: Handle,
    ) -> Result<(), quic_error::Error> {
        println!("building packet for connection {:?}", connection_handle);

        let connection = match self.connections.get_mut(connection_handle) {
            Some(c) => c,
            None => {
                return Err(quic_error::Error::unknown_connection(
                    "error while retrieving connection",
                ));
            }
        };

        let mut buffer = [0u8; 65535];

        let packet_length = connection.fill_datagram(&mut buffer).unwrap();

        /*let size = match self
            .socket
            .send_to(&buffer[..packet_length], connection.remote)
        {
            Ok(size) => size,
            Err(error) => {
                return Err(quic_error::Error::socket_error(format!("{}", error)));
            }
        };

        println!("sent {} bytes to {:?}", size, connection.remote);
        */

        Ok(())
    }
}

pub struct Connection {
    //side
    side: Side,

    //quic version
    version: u32,

    //tls13 session via rustls and keying material
    tls_session: RustlsConnection,
    next_secrets: Option<rustls::quic::Secrets>,
    prev_1rtt_keys: Option<PacketKeySet>,
    next_1rtt_keys: Option<PacketKeySet>,
    initial_keyset: Keys,
    zero_rtt_keyset: Option<Keys>,

    //connection state
    state: ConnectionState,

    // First received dcid
    initial_dcid: ConnectionId,
    // First received scid
    initial_remote_scid: ConnectionId,
    // First generated scid after handshake receive
    initial_local_scid: ConnectionId,
    // Retry Source Connection Id
    rscid: Option<ConnectionId>,

    // Packet number spaces, inital, handshake, 1-RTT
    packet_spaces: [PacketNumberSpace; 3],
    current_space: usize,

    // Physical address of connection peer
    remote: SocketAddr,

    // Packet stats
    recved: u64,
    sent: u64,
    lost: u64,

    //0-Rtt enabled
    zero_rtt_enabled: bool,
}

impl Connection {
    pub fn new(
        side: Side,
        version: u32,
        tls_session: RustlsConnection,
        initial_keyset: Keys,
        initial_dcid: ConnectionId,
        initial_remote_scid: ConnectionId,
        initial_local_scid: ConnectionId,
        remote_address: SocketAddr,
        initial_space: PacketNumberSpace,
    ) -> Self {
        Connection {
            side,
            version,
            tls_session,
            next_secrets: None,
            next_1rtt_keys: None,
            prev_1rtt_keys: None,
            zero_rtt_keyset: None,
            initial_keyset,
            state: ConnectionState::Handshake,
            initial_dcid,
            initial_remote_scid,
            initial_local_scid,
            rscid: None,
            packet_spaces: [
                initial_space,
                PacketNumberSpace::new(true),
                PacketNumberSpace::new(false),
            ],
            current_space: SPACE_ID_INITIAL,
            remote: remote_address,
            recved: 0,
            sent: 0,
            lost: 0,
            zero_rtt_enabled: false,
        }
    }

    //fully decrypts packet header and payload, does tls stuff and passes packet to process_payload
    pub fn recv(
        &mut self,
        header: &mut Header,
        payload: &mut OctetsMut<'_>,
    ) -> Result<(), quic_error::Error> {
        //decrypt header and payload

        self.process_payload(header, payload);

        // if space is handshake, call to write crypto after processing payload

        Ok(())
    }

    //accepts new connection, passes payload to process_payload
    pub fn accept(
        &mut self,
        header: &Header,
        payload: &mut OctetsMut<'_>,
    ) -> Result<(), quic_error::Error> {
        self.process_payload(header, payload);

        println!(
            "transport parameters from peer: {:x?}",
            self.tls_session.quic_transport_parameters().unwrap(),
        );

        self.generate_crypto_data();

        // generate crypto data again for ee, cert, cv, fin
        Ok(())
    }

    // TODO change to just &Octets, because we dont need to modify the buffer after decrypting
    fn process_payload(&mut self, header: &Header, payload: &mut OctetsMut<'_>) {
        //TODO check if packet is ack eliciting
        let mut ack_eliciting = false;

        while payload.peek_u8().is_ok() {
            let frame_code = payload.get_u8().unwrap();

            //check if frame is ack eliciting
            ack_eliciting = !matches!(frame_code, 0x00 | 0x02 | 0x03 | 0x1c | 0x1d);

            match frame_code {
                0x00 => continue, //PADDING
                0x01 => continue, //PING
                0x02 | 0x03 => {
                    let _ack = AckFrame::from_bytes(&frame_code, payload);
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
                    if stream_frame.offset.is_some() {
                        (stream_data, _) = payload
                            .split_at(stream_frame.offset.unwrap() as usize)
                            .unwrap();
                    }

                    println!(
                        "stream_id {:#x} len {:#x} data {:#x?}",
                        stream_frame.stream_id,
                        stream_data.len(),
                        stream_data
                    );
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
                    let _new_connection_id = NewConnectionIdFrame::from_bytes(&frame_code, payload);
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
                    //self.handshake_done = true;
                } // HANDSHAKE_DONE
                _ => eprintln!(
                    "Error while processing frames: unrecognised frame {:#x} at {:#x}",
                    frame_code,
                    payload.off()
                ),
            }
        }

        if ack_eliciting {
            self.packet_spaces[self.current_space]
                .outgoing_acks
                .push(header.packet_num.into());
        }
    }

    fn process_crypto_data(&mut self, crypto_frame: &CryptoFrame) {
        println!("Crypto Frame Data: {:x?}", crypto_frame.vec());

        match self.tls_session.read_hs(crypto_frame.data()) {
            Ok(()) => println!("Successfully read handshake data"),
            Err(err) => {
                eprintln!("Error reading crypto data: {}", err);
                eprintln!("{:?}", self.tls_session.alert().unwrap());
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
            println!("Handshake data has been read and proccessed successfully");
            let _ = true;
        }
    }

    fn generate_crypto_data(&mut self) {
        //get mutable reference to crypto buffer
        let buf: &mut Vec<u8> = self.packet_spaces[self.current_space]
            .outgoing_crypto_data
            .as_mut()
            .unwrap();

        //writing handshake data prompts a keychange because the packet number spce is promoted
        let kc = match self.tls_session.write_hs(buf) {
            Some(kc) => kc,
            None => panic!("Error writing handshake data"),
        };

        //get keys from keychange
        let keys = match kc {
            KeyChange::Handshake { keys } => keys,
            KeyChange::OneRtt { keys, next } => {
                self.next_secrets = Some(next);
                keys
            }
        };

        // if space id is DATA, only the packet payload keys update, not the header keys
        if (self.current_space + 1) == SPACE_ID_DATA {
            self.next_1rtt_keys = Some(
                self.next_secrets
                    .as_mut()
                    .expect("handshake should be completed and next secrets availible")
                    .next_packet_keys(),
            )
        }

        //"upgrade" to next packet number space with new keying material
        self.packet_spaces[self.current_space + 1].keys = Some(keys);

        println!(
            "generated server hello (len {:x?}): {:x?}",
            buf.len(),
            buf.to_vec()
        );

        //advance space
        self.current_space += 1;
    }

    fn fill_datagram(&mut self, buffer: &mut [u8]) -> Result<usize, quic_error::Error> {
        // detect if packet needs to be sent if current space is handshake and initial has outstanding_crypto_data
        let mut size: usize = 0;

        for space_id in 0..(self.current_space + 1) {
            size += self.build_packet_in_space(&mut buffer[size..], space_id)?;
        }

        Ok(size)
    }

    fn build_packet_in_space(
        &mut self,
        buffer: &mut [u8],
        packet_number_space: usize,
    ) -> Result<usize, quic_error::Error> {
        println!("Building packet in space {:#x}", packet_number_space);

        let mut buf = octets::OctetsMut::with_slice(buffer);

        //calculate packet number length
        let mut packet_num_length: u8 = 0;
        match self.packet_spaces[packet_number_space].next_pkt_num {
            0x00..=0xff => packet_num_length = 0,
            0x0100..=0xffff => packet_num_length = 1,
            0x010000..=0xffffff => packet_num_length = 2,
            0x01000000..=0xffffffff => packet_num_length = 3,
            _ => unreachable!("packet number exceeds maximum encodable value"),
        }

        //TODO: figure out proper way to get current cids
        let dcid: &ConnectionId = &self.initial_remote_scid;
        let scid: &ConnectionId = &self.initial_local_scid;

        //pre-encode header
        match Header::new_long_header(
            0x00,
            packet_num_length,
            1,
            self.packet_spaces[packet_number_space].next_pkt_num,
            dcid,
            scid,
            None,
            1200, //use minimum packet length to pre-encode packet length
        )?
        .to_bytes(&mut buf)
        {
            Ok(()) => (),
            Err(error) => {
                return Err(quic_error::Error::header_encoding_error(format!(
                    "buffer has unsufficient size to encode header: {}",
                    error
                )))
            }
        };

        let header_length = buf.off();

        //calculate packet number offset
        let packet_length_offset = buf.off() - packet_num_length as usize - 2;

        let max_packet_size: usize = 16383; //max size for packet length encoding with 2 bytes

        //fill payload
        let mut payload_length = self.populate_packet_payload(&mut buf, packet_number_space)?;

        //calculate padding, buffer is zeroed out anyway, so just increasing the length is
        //sufficient
        if payload_length < 1200 {
            payload_length = 1200;
        }

        if (payload_length + header_length) > (max_packet_size - packet_num_length as usize) {
            return Err(quic_error::Error::packet_size_error(format!(
                "max packet length exceeded with {}",
                payload_length
            )));
        }

        //reencode actual packet length
        octets::OctetsMut::with_slice(
            &mut buf.as_mut()[packet_length_offset..packet_length_offset + 2],
        )
        .put_varint_with_len(payload_length.try_into().unwrap(), 2)
        .unwrap();

        //update packet number space
        self.packet_spaces[packet_number_space].next_pkt_num += 1;

        //encrypt

        //Ok(header_length + payload_length)
        Ok(0)
    }

    fn populate_packet_payload(
        &mut self,
        buf: &mut octets::OctetsMut<'_>,
        packet_number_space: usize,
    ) -> Result<usize, quic_error::Error> {
        let mut size = 0;

        //CRYPTO
        if let Some(crypto_buffer) = &self.packet_spaces[packet_number_space].outgoing_crypto_data {
            if !crypto_buffer.is_empty() {
                let s =
                    match packet::encode_frame(&CryptoFrame::new(0, crypto_buffer.to_vec()), buf) {
                        Ok(s) => s,
                        Err(error) => {
                            return Err(quic_error::Error::packet_size_error(format!(
                                "insufficient sized buffer for CRYPTO frame ({})",
                                error
                            )))
                        }
                    };
                println!("wrote crypto frame with size {:?}", s);
                size += s;
            }
        }

        //ACK
        if !self.packet_spaces[packet_number_space]
            .outgoing_acks
            .is_empty()
        {
            //sort outgoing acks in reverse to ease range building
            self.packet_spaces[packet_number_space]
                .outgoing_acks
                .sort_by(|a, b| b.cmp(a));

            //directly generate ack frame from packet number vector
            let ack_frame = AckFrame::from_packet_number_vec(
                &self.packet_spaces[packet_number_space].outgoing_acks,
            );

            //clear vector as packet numbers are now ack'ed
            self.packet_spaces[packet_number_space]
                .outgoing_acks
                .clear();

            let s = match packet::encode_frame(&ack_frame, buf) {
                Ok(s) => s,
                Err(error) => {
                    return Err(quic_error::Error::packet_size_error(format!(
                        "insufficient sized buffer for ack frame ({})",
                        error
                    )))
                }
            };

            println!("wrote ack frame with size {:?}", s);
            size += s;
        };

        Ok(size)
    }
}

pub enum ConnectionState {
    Handshake,
    Connected,
    Terminated,
    Emtpying,
    Empty,
}

//RFC 9000 section 12.3. we have 3 packet number spaces: initial, handshake & 1-RTT
pub struct PacketNumberSpace {
    keys: Option<Keys>,

    outgoing_acks: Vec<u64>,

    //TODO make arc around vec to avoid copying
    outgoing_crypto_data: Option<Vec<u8>>,

    next_pkt_num: u32,
}

impl PacketNumberSpace {
    pub fn new(with_crypto_buffer: bool) -> Self {
        Self {
            keys: None,
            outgoing_acks: Vec::new(),
            outgoing_crypto_data: match with_crypto_buffer {
                true => Some(Vec::new()),
                false => None,
            },
            next_pkt_num: 0,
        }
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

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_long_initial_header() {
        let result = Header::new_long_header(
            0x00,
            0x03,
            1,
            0,
            &ConnectionId::from_vec(Vec::new()),
            &ConnectionId::from_vec(Vec::new()),
            None,
            1280,
        )
        .unwrap();

        assert_eq!(result.hf, 0b11000011);
    }

    #[test]
    fn create_short_initial_header() {
        let result = Header::new_short_header(
            0x03,
            0x01,
            0x01,
            1,
            0,
            &ConnectionId::from_vec(Vec::new()),
            1280,
        )
        .unwrap();

        assert_eq!(result.hf, 0b01100111);
    }

    #[test]
    fn test_length_matching() {
        let x = 256;
        let mut length = 0;

        match x {
            ..=0xff => length = 0,
            0x0100..=0xffff => length = 1,
            _ => unreachable!("unreachable size of next packet num"),
        }

        assert_eq!(length, 1);
    }
}
