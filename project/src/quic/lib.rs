mod frame;
mod quic_error;
mod stream;
mod token;
mod transport_parameters;

use crate::frame::Frame;
use frame::{
    AckFrame, ConnectionCloseFrame, CryptoFrame, NewConnectionIdFrame, NewTokenFrame, StreamFrame,
};
use octets::{BufferTooShortError, OctetsMut};
use rand::RngCore;
use ring::aead::quic;
use rustls::{
    quic::{
        Connection as RustlsConnection, HeaderProtectionKey, KeyChange, Keys, PacketKeySet, Version,
    },
    Side,
};
use std::{
    collections::HashMap,
    fmt,
    net::{SocketAddr, UdpSocket},
};

const LS_TYPE_BIT: u8 = 0x80;
const TYPE_MASK: u8 = 0x30;
const PKT_NUM_LENGTH_MASK: u8 = 0x03;

const MAX_PKT_NUM_LEN: u8 = 4;
const MAX_CID_SIZE: usize = 20;
const SAMPLE_LEN: usize = 16;

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

/*
 * Primary object in library. Can act as client or server. Can accept incoming
 * connections or connect to a server.
 */
pub struct Endpoint {
    socket: UdpSocket,

    //server config for rustls. Will have to be updated to allow client side endpoint
    server_config: Option<rustls::ServerConfig>,
    //RFC 2104, used to generate reset tokens from connection ids
    hmac_reset_key: ring::hmac::Key,

    //stores connection handles
    conn_db: HashMap<ConnectionId, Handle>,
    connections: Vec<Connection>,
}

impl Endpoint {
    pub fn local_server(addr: &str) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = rustls::PrivateKey(cert.serialize_private_key_der());
        let cert = rustls::Certificate(cert.serialize_der().unwrap());

        Self::server(addr, cert, key)
    }

    pub fn server(addr: &str, certificate: rustls::Certificate, pkey: rustls::PrivateKey) -> Self {
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

        let mut hmac_reset_key = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut hmac_reset_key);

        Endpoint {
            socket: UdpSocket::bind(addr).expect("Error: couldn't bind UDP socket to address"),
            server_config: Some(server_cfg),
            hmac_reset_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &hmac_reset_key),
            conn_db: HashMap::new(),
            connections: Vec::new(),
        }
    }

    pub fn client() -> Self {
        panic!("Client endpoint not yet implemented!")
    }

    // handles a single incoming UDP datagram
    pub fn recv(&mut self) -> Result<Event, quic_error::Error> {
        // TODO: handle coalescing inital, 0-rtt and handshake packets, max udp packet size is 65kb
        let mut buffer = [0u8; 65536];

        let (size, src_addr) = match self.socket.recv_from(&mut buffer) {
            Ok((size, src_addr)) => (size, src_addr),
            Err(error) => {
                println!("Error while receiving datagram: {:?}", error);
                return Err(quic_error::Error::socket_error("receiving packet"));
            }
        };
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
        if let Some(h) =
            self.get_connection_handle(&head.dcid, &src_addr, ((head.hf & LS_TYPE_BIT) >> 7) != 0)
        {
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

        let (header_raw, mut payload_cipher) = octet_buffer.split_at(head.length).unwrap();

        //cut off trailing 0s from buffer
        let (mut payload_cipher, _) = payload_cipher
            .split_at(head.packet_length - head.packet_num_length as usize)
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
                std::sync::Arc::new(self.server_config.as_ref().unwrap().clone()),
                rustls::quic::Version::V1,
                data.to_vec(),
            )
            .unwrap(),
        );

        let initial_space: PacketNumberSpace = PacketNumberSpace {
            keys: Some(Keys::initial(Version::V1, &head.dcid.id, Side::Server)),
            ..PacketNumberSpace::new(true)
        };

        let new_ch = self
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
            .unwrap();

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

        let mut buffer = [0u8; 65536];

        let packet_length = connection.fill_datagram(&mut buffer)?;

        let size = match self
            .socket
            .send_to(&buffer[..packet_length], connection.remote)
        {
            Ok(size) => size,
            Err(error) => {
                return Err(quic_error::Error::socket_error(format!("{}", error)));
            }
        };

        println!("sent {} bytes to {:?}", size, connection.remote);

        Ok(())
    }
}

//struct Connection {

//}

struct Connection {
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
            "wr {:?} ww {:?} ih {:?} tpp: {:?}",
            self.tls_session.wants_read(),
            self.tls_session.wants_write(),
            self.tls_session.is_handshaking(),
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
            self.packet_spaces[self.current_space as usize]
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
        let buf: &mut Vec<u8> = self.packet_spaces[self.current_space as usize]
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
        self.packet_spaces[(self.current_space + 1) as usize].keys = Some(keys);

        println!(
            "Is this the Server Hello with len {:x?}: {:x?}",
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
            size += match self.build_packet_in_space(buffer, space_id) {
                Ok(s) => s,
                Err(error) => return Err(error),
            };
        }

        Ok(size)
    }

    fn build_packet_in_space(
        &mut self,
        buffer: &mut [u8],
        packet_number_space: usize,
    ) -> Result<usize, quic_error::Error> {
        println!("Building packet in space {:#x}", packet_number_space);

        let pns = &mut self.packet_spaces[self.current_space];
        let buf = octets::OctetsMut::with_slice(buffer);

        //build header

        //build payload

        Ok(buf.off())
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

    max_acked_pkt: Option<u64>,

    next_pkt_num: u64,
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
            max_acked_pkt: None,
            next_pkt_num: 0,
        }
    }
}

pub struct Header {
    hf: u8, //header form and version specific bits
    version: u32,
    dcid: ConnectionId,
    scid: Option<ConnectionId>,

    //The following fields are under header protection
    packet_num: u32,
    packet_num_length: u8,
    token: Option<Vec<u8>>,

    //packet length including packet_num
    packet_length: usize,

    //header length including packet_num
    length: usize,
}

impl Header {
    pub fn new_long_header(
        long_header_type: u8,
        packet_num_length: u8,
        version: u32,
        packet_num: u32,
        dcid: &ConnectionId,
        scid: Option<&ConnectionId>,
        token: Option<Vec<u8>>,
        packet_length: usize,
    ) -> Result<Self, quic_error::Error> {
        if !matches!(long_header_type, 0x00..=0x03) {
            return Err(quic_error::Error::header_encoding_error(format!(
                "unsupported long header type {:?}",
                long_header_type
            )));
        }

        if !matches!(packet_num_length, 0x01..=MAX_PKT_NUM_LEN) {
            return Err(quic_error::Error::header_encoding_error(format!(
                "unsupported packet number length {:?}",
                packet_num_length
            )));
        }

        Ok(Header::new(
            0x01,
            long_header_type,
            packet_num_length,
            0x00,
            0x00,
            version,
            dcid,
            scid,
            packet_num,
            token,
            packet_length,
        ))
    }

    pub fn new_short_header(
        packet_num_length: u8,
        spin_bit: u8,
        key_phase: u8,
        version: u32,
        packet_num: u32,
        dcid: &ConnectionId,
        scid: Option<&ConnectionId>,
        packet_length: usize,
    ) -> Result<Self, quic_error::Error> {
        if !matches!(spin_bit, 0x00 | 0x01) {
            return Err(quic_error::Error::header_encoding_error(format!(
                "unsupported header spin bit {:?}",
                spin_bit
            )));
        }

        if !matches!(key_phase, 0x00 | 0x01) {
            return Err(quic_error::Error::header_encoding_error(format!(
                "unsupported header key phase {:?}",
                key_phase
            )));
        }

        if !matches!(packet_num_length, 0x01..=MAX_PKT_NUM_LEN) {
            return Err(quic_error::Error::header_encoding_error(format!(
                "unsupported packet number length {:?}",
                packet_num_length
            )));
        }

        Ok(Header::new(
            0x00,
            0x00,
            packet_num_length,
            spin_bit,
            key_phase,
            version,
            dcid,
            scid,
            packet_num,
            None,
            packet_length,
        ))
    }

    //not public because values are not error checked
    fn new(
        header_form: u8,
        long_header_type: u8,
        packet_num_length: u8,
        spin_bit: u8,
        key_phase: u8,
        version: u32,
        dcid: &ConnectionId,
        scid: Option<&ConnectionId>,
        packet_num: u32,
        token: Option<Vec<u8>>,
        packet_length: usize,
    ) -> Self {
        let mut hf: u8 = 0x00;

        //set header form bit
        hf |= header_form << 7;

        //set fixed bit for every header type
        hf |= 1 << 6;

        hf |= spin_bit << 5;

        hf |= long_header_type << 4;

        hf |= key_phase << 2;

        hf |= packet_num_length;

        Self {
            hf,
            version,
            dcid: dcid.clone(),
            scid: scid.cloned(),
            packet_num,
            packet_num_length,
            token,
            packet_length,
            length: 0,
        }
    }

    pub fn decrypt(
        &mut self,
        b: &mut octets::OctetsMut,
        header_key: &HeaderProtectionKey,
    ) -> Result<(), BufferTooShortError> {
        let mut pn_and_sample = b.peek_bytes_mut(MAX_PKT_NUM_LEN as usize + SAMPLE_LEN)?;
        let (mut pn_cipher, sample) = pn_and_sample.split_at(MAX_PKT_NUM_LEN as usize)?;

        match header_key.decrypt_in_place(sample.as_ref(), &mut self.hf, pn_cipher.as_mut()) {
            Ok(_) => (),
            Err(error) => panic!("Error decrypting header: {}", error),
        }

        //write decrypted first byte back into buffer
        let (mut first_byte, _) = b.split_at(1)?;
        first_byte.as_mut()[0] = self.hf;

        self.packet_num_length = (self.hf & PKT_NUM_LENGTH_MASK) + 1;

        self.length += self.packet_num_length as usize;

        self.packet_num = match self.packet_num_length {
            1 => u32::from(b.get_u8()?),
            2 => u32::from(b.get_u16()?),
            3 => b.get_u24()?,
            4 => b.get_u32()?,
            _ => return Err(BufferTooShortError),
        };

        Ok(())
    }

    //TODO retry & version negotiation packets
    pub fn to_bytes(&self, b: &mut octets::OctetsMut) -> Result<(), BufferTooShortError> {
        b.put_u8(self.hf)?;

        if let Some(scid) = &self.scid {
            //long header
            b.put_u32(self.version)?;
            b.put_u8(self.dcid.len().try_into().unwrap())?;
            b.put_bytes(self.dcid.as_slice())?;
            b.put_u8(scid.len().try_into().unwrap())?;
            b.put_bytes(scid.as_slice())?;

            //initial
            if let Some(token) = &self.token {
                b.put_varint(token.len().try_into().unwrap())?;
                b.put_bytes(token)?;
            }

            //packet length
            b.put_varint(self.packet_length as u64)?;
        } else {
            //short header
            b.put_bytes(self.dcid.as_slice())?;
        }

        //packet number
        match self.packet_num_length {
            1 => b.put_u8(self.packet_num.try_into().unwrap())?,
            2 => b.put_u16(self.packet_num.try_into().unwrap())?,
            3 => b.put_u24(self.packet_num)?,
            4 => b.put_u32(self.packet_num)?,
            _ => unreachable!(
                "unsupported packet number length {}",
                self.packet_num_length
            ),
        };

        Ok(())
    }

    pub fn from_bytes(
        b: &mut octets::OctetsMut,
        dcid_len: usize,
    ) -> Result<Header, BufferTooShortError> {
        let hf = b.get_u8()?;

        if ((hf & LS_TYPE_BIT) >> 7) == 0 {
            //short packet
            let dcid = b.get_bytes(dcid_len)?;

            return Ok(Header {
                hf,
                version: 0,
                dcid: dcid.to_vec().into(),
                scid: None,
                packet_num: 0,
                packet_num_length: 0,
                token: None,
                packet_length: 0, //TODO
                length: b.off(),
            });
        }

        let v = b.get_u32()?;

        let dcid_length = b.get_u8()?; // TODO check for max cid len of 20
        let dcid = b.get_bytes(dcid_length as usize)?.to_vec();

        let scid_length = b.get_u8()?; // TODO check for max cid len of 20
        let scid = b.get_bytes(scid_length as usize)?.to_vec();

        let mut tok: Option<Vec<u8>> = None;

        match (hf & TYPE_MASK) >> 4 {
            0x00 => {
                // Initial
                tok = Some(b.get_bytes_with_varint_length()?.to_vec());
            }
            0x01 => (), // Zero-RTT
            0x02 => (), // Handshake
            0x03 => (), // Retry
            _ => panic!("Fatal Error with packet type"),
        }

        let pkt_length = b.get_varint()?;

        Ok(Header {
            hf,
            version: v,
            dcid: dcid.into(),
            scid: Some(scid.into()),
            packet_num: 0,
            packet_num_length: 0,
            token: tok,
            packet_length: pkt_length as usize,
            length: b.off(),
        })
    }

    fn debug_print(&self) {
        println!(
            "{:#04x?} version: {:#06x?} pn: {:#010x?} dcid: 0x{} scid: 0x{} token:{:x?} length:{:?} header_length:{:?}",
            ((self.hf & TYPE_MASK) >> 4),
            self.version,
            self.packet_num,
            self.dcid
                .id
                .iter()
                .map(|val| format!("{:x}", val))
                .collect::<Vec<String>>()
                .join(""),
            self.scid
                .clone()
                .unwrap_or(ConnectionId::from_vec(Vec::new()))
                .id
                .iter()
                .map(|val| format!("{:x}", val))
                .collect::<Vec<String>>()
                .join(""),
            self.token.as_ref().unwrap(),
            self.packet_length,
            self.length,
        );
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
            Some(&ConnectionId::from_vec(Vec::new())),
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
            Some(&ConnectionId::from_vec(Vec::new())),
            1280,
        )
        .unwrap();

        assert_eq!(result.hf, 0b01100111);
    }
}
