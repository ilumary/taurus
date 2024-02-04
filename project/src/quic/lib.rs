mod frame;
mod quic_error;
mod token;
mod transport_parameters;

use crate::frame::Frame;
use frame::{
    AckFrame, ConnectionCloseFrame, CryptoFrame, NewConnectionIdFrame, NewTokenFrame, StreamFrame,
};
use octets::{BufferTooShortError, OctetsMut};
use rand::RngCore;
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

const MAX_PKT_NUM_LEN: usize = 4;
const MAX_CID_SIZE: usize = 20;
const SAMPLE_LEN: usize = 16;

const SPACE_ID_INITIAL: u8 = 0x01;
const SPACE_ID_HANDSHAKE: u8 = 0x02;
const SPACE_ID_DATA: u8 = 0x03;

type Handle = usize;

/*
 * Primary object in library. Can act as client or server. Can accept incoming
 * connections or connect to a server.
 */
pub struct Endpoint {
    socket: UdpSocket,
    socket_addr: SocketAddr,

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

        let mut hmac_reset_key = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut hmac_reset_key);

        Endpoint {
            socket: UdpSocket::bind(addr).expect("Error: couldn't bind UDP socket to address"),
            socket_addr: addr.parse().unwrap(),
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
    pub fn recv(&mut self) {
        // TODO: handle coalescing inital, 0-rtt and handshake packets, max udp packet size is 65kb
        let mut buffer = [0u8; 65536];

        let (size, src_addr) = match self.socket.recv_from(&mut buffer) {
            Ok((size, src_addr)) => (size, src_addr),
            Err(error) => {
                println!("Error while receiving datagram: {:?}", error);
                return;
            }
        };
        println!("Received {:?} bytes from {:?}", size, src_addr);

        let mut octet_buffer = OctetsMut::with_slice(&mut buffer);

        //println!("\nRAW\n{:x?}", octet_buffer); // offset 0

        //check if most significant bit is 1 or 0, if 0 => short packet => have to get cid len
        //somehow
        let mut head: Header = match Header::parse_from_bytes(&mut octet_buffer, 0) {
            Ok(h) => h,
            Err(error) => panic!("Error: {}", error),
        };

        //match connection if one already exists
        if let Some(h) =
            self.get_connection_handle(&head.dcid, &src_addr, ((head.hf & LS_TYPE_BIT) >> 7) != 0)
        {
            //connection exists, pass packet to connection
            println!("Found existing connection for {}", &head.dcid);
            match self
                .connections
                .get_mut(h)
                .unwrap()
                .recv(&head, &mut octet_buffer)
            {
                Ok(()) => return,
                Err(error) => panic!("Error processing packet: {}", error),
            }
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
            .split_at(head.packet_length - head.packet_num_length)
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

        let initial_space: PacketSpace = PacketSpace {
            keys: Some(Keys::initial(Version::V1, &head.dcid.id, Side::Server)),
            ..PacketSpace::new()
        };

        let new_ch = self
            .create_connection(
                Side::Server,
                orig_dcid,
                head.scid.clone(),
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
            Ok(()) => (),
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
        inital_dcid: ConnectionId,
        inital_scid: ConnectionId,
        inital_loc_scid: ConnectionId,
        tls_session: RustlsConnection,
        inital_keyset: Keys,
        initial_space: PacketSpace,
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

    pub fn _send() {}
}

pub struct Connection {
    //side
    side: Side,

    //tls13 session via rustls
    tls_session: RustlsConnection,
    next_secrets: Option<rustls::quic::Secrets>,

    prev_1rtt_keys: Option<PacketKeySet>,
    next_1rtt_keys: Option<PacketKeySet>,
    initial_keyset: Keys,
    zero_rtt_keyset: Option<Keys>,

    //connection state
    state: ConnectionState,

    //active connection ids
    active_cids: Vec<ConnectionId>,

    // First received dcid
    initial_dcid: ConnectionId,
    // First received scid
    initial_remote_scid: ConnectionId,
    // First generated scid after handshake receive
    initial_local_scid: ConnectionId,
    // Retry Source Connection Id
    rscid: Option<ConnectionId>,

    // Packet number spaces, inital, handshake, 1-RTT
    packet_spaces: [PacketSpace; 3],
    current_space: u8,

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
        tls_session: RustlsConnection,
        initial_keyset: Keys,
        initial_dcid: ConnectionId,
        initial_remote_scid: ConnectionId,
        initial_local_scid: ConnectionId,
        remote_address: SocketAddr,
        initial_space: PacketSpace,
    ) -> Self {
        Connection {
            side,
            tls_session,
            next_secrets: None,
            next_1rtt_keys: None,
            prev_1rtt_keys: None,
            zero_rtt_keyset: None,
            initial_keyset,
            state: ConnectionState::Handshake,
            active_cids: vec![initial_remote_scid.clone()],
            initial_dcid,
            initial_remote_scid,
            initial_local_scid,
            rscid: None,
            packet_spaces: [initial_space, PacketSpace::new(), PacketSpace::new()],
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
        header: &Header,
        payload: &mut OctetsMut<'_>,
    ) -> Result<(), quic_error::Error> {
        self.process_payload(payload);

        // if space is handshake, call to write crypto after processing payload

        Ok(())
    }

    //accepts new connection, passes payload to process_payload
    pub fn accept(
        &mut self,
        header: &Header,
        payload: &mut OctetsMut<'_>,
    ) -> Result<(), quic_error::Error> {
        self.process_payload(payload);
        self.generate_crypto_data();
        Ok(())
    }

    fn process_payload(&mut self, payload: &mut OctetsMut<'_>) {
        while payload.peek_u8().is_ok() {
            let frame_code = payload.get_u8().unwrap();
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

                    //isolate stream data if offset is present
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
                } //MAX_StREAM_DATA
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
    }

    fn process_crypto_data(&mut self, crypto_frame: &CryptoFrame) {
        match self.tls_session.read_hs(crypto_frame.data()) {
            Ok(()) => println!("Successfully read handshake data"),
            Err(err) => eprintln!("Error reading crypto data: {}", err),
        }
    }

    fn generate_crypto_data(&mut self) {
        let mut buf = Vec::new();
        let kc = match self.tls_session.write_hs(&mut buf) {
            Some(kc) => kc,
            None => panic!("Error writing handshake data"),
        };

        let keys = match kc {
            KeyChange::Handshake { keys } => keys,
            KeyChange::OneRtt { keys, next } => {
                self.next_secrets = Some(next);
                keys
            }
        };

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

        //advance space
        self.current_space += 1;

        println!("{:#x?}", buf);
    }

    pub fn _send() {}
}

pub enum ConnectionState {
    Handshake,
    Connected,
    Terminated,
    Emtpying,
    Empty,
}

//RFC 9000 section 12.3. we have 3 packet number spaces: initial, handshake & 1-RTT
pub struct PacketSpace {
    keys: Option<Keys>,

    max_recved_pkt_num: usize,

    max_acked_pkt: Option<usize>,

    next_pkt_num: usize,
}

impl PacketSpace {
    pub fn new() -> Self {
        Self {
            keys: None,
            max_recved_pkt_num: 0,
            max_acked_pkt: None,
            next_pkt_num: 0,
        }
    }
}

pub struct Header {
    hf: u8, //header form and version specific bits
    version: u32,
    dcid: ConnectionId,
    scid: ConnectionId,

    //The following fields are under header protection
    packet_num: u32,
    packet_num_length: usize,
    token: Option<Vec<u8>>,

    //packet length including packet_num
    packet_length: usize,

    //header length including packet_num
    length: usize,
}

impl Header {
    pub fn decrypt(
        &mut self,
        b: &mut octets::OctetsMut,
        header_key: &HeaderProtectionKey,
    ) -> Result<(), BufferTooShortError> {
        let mut pn_and_sample = b.peek_bytes_mut(MAX_PKT_NUM_LEN + SAMPLE_LEN)?;
        let (mut pn_cipher, sample) = pn_and_sample.split_at(MAX_PKT_NUM_LEN)?;

        match header_key.decrypt_in_place(sample.as_ref(), &mut self.hf, pn_cipher.as_mut()) {
            Ok(_) => (),
            Err(error) => panic!("Error decrypting header: {}", error),
        }

        //write decrypted first byte back into buffer
        let (mut first_byte, _) = b.split_at(1)?;
        first_byte.as_mut()[0] = self.hf;

        self.packet_num_length = usize::from((self.hf & PKT_NUM_LENGTH_MASK) + 1);

        self.length += self.packet_num_length;

        self.packet_num = match self.packet_num_length {
            1 => u32::from(b.get_u8()?),
            2 => u32::from(b.get_u16()?),
            3 => b.get_u24()?,
            4 => b.get_u32()?,
            _ => return Err(BufferTooShortError),
        };

        Ok(())
    }

    pub fn parse_from_bytes(
        b: &mut octets::OctetsMut,
        dcid_len: usize,
    ) -> Result<Header, BufferTooShortError> {
        let hf = b.get_u8()?;
        let pkt_length = u64::try_from(b.cap()).unwrap_or(0);

        if ((hf & LS_TYPE_BIT) >> 7) == 0 {
            //short packet
            let dcid = b.get_bytes(dcid_len)?;

            return Ok(Header {
                hf,
                version: 0,
                dcid: dcid.to_vec().into(),
                scid: ConnectionId::default(),
                packet_num: 0,
                packet_num_length: 0,
                token: None,
                packet_length: pkt_length as usize,
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
            scid: scid.into(),
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
    pub fn as_arr(&self) -> &[u8] {
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
