#![allow(dead_code)]

mod quic_error;
mod transport_parameters;

use octets::{BufferTooShortError, OctetsMut};
use rand::RngCore;
use rustls::quic::{Connection as RustlsConnection, HeaderProtectionKey, Keys, Version};
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

//most systems default to IPv6
const MAX_PACKET_SIZE_IPV4: usize = 1472;
const MAX_PACKET_SIZE_IPV6: usize = 1330;

type Handle = usize;

/*
 * Primary object in library. Can be contructed as client or server. Can accept incoming
 * connections or connect to a server.
 */
pub struct Endpoint {
    socket: UdpSocket,
    socket_addr: SocketAddr,

    //server config for rustls. Will have to be updated to allow client side endpoint
    server_config: Option<rustls::ServerConfig>,

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

        Endpoint {
            socket: UdpSocket::bind(addr).expect("Error: couldn't bind UDP socket to address"),
            socket_addr: addr.parse().unwrap(),
            server_config: Some(server_cfg),
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
            match self.connections.get_mut(h).unwrap().recv() {
                Ok(()) => return,
                Err(error) => panic!("Error processing packet: {}", error),
            }
        }

        //handle new connection

        //get initial keys
        let ikp = Keys::initial(Version::V1, &head.dcid.id, rustls::Side::Server);

        match head.decrypt(&mut octet_buffer, ikp.remote.header) {
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
        match ikp.remote.packet.decrypt_in_place(
            head.packet_num.into(),
            header_raw.as_ref(),
            payload_cipher.as_mut(),
        ) {
            Ok(_) => (),
            Err(error) => panic!("Error decrypting packet body {}", error),
        };

        let new_connection_handle = self.connections.len();
        let loc_cid = ConnectionId::generate_with_length(head.dcid.len());
        let orig_dcid = head.dcid.clone();

        let mut conn = RustlsConnection::Server(
            rustls::quic::ServerConnection::new(
                std::sync::Arc::new(self.server_config.as_ref().unwrap().clone()),
                rustls::quic::Version::V1,
                vec![],
            )
            .unwrap(),
        );

        // handle frames
        loop {
            match octet_buffer.peek_u8() {
                Ok(0x06) => {
                    // CRYPTO_FRAME
                    println!("Discovered Crypto frame...");
                    let frame = octet_buffer.get_u8().unwrap();
                    let off = octet_buffer.get_varint().unwrap();
                    let len = octet_buffer.get_varint().unwrap();
                    let tp = transport_parameters::TransportParameter::decode(&mut octet_buffer)
                        .unwrap();
                    println!("{}", tp);

                    /*match conn.read_hs(octet_buffer.as_ref()) {
                        Ok(_) => (),
                        Err(error) => panic!("Error while consuming handshake data {}", error),
                    };

                    println!("{:x?}", conn.quic_transport_parameters());*/
                    break;
                }
                Ok(0x00) => {
                    break;
                }
                _ => panic!("Fatal Error while parsing frames: unknown frame type"),
            }
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

    fn create_connection(&mut self) -> Result<Handle, quic_error::Error> {
        Ok(0)
    }

    pub fn _send() {}
}

pub struct Connection {
    // tls13 session via rustls
    tls_session: Option<RustlsConnection>,
    next_secrets: Option<rustls::quic::Secrets>,
    handshake_data_received: bool,

    // Connection Identifiers
    scids: Vec<ConnectionId>,
    dcids: Vec<ConnectionId>,

    // First Destination Connection Id
    fdcid: ConnectionId,
    // Retry Source Connection Id
    rscid: Option<ConnectionId>,

    next_packet_num: u64,

    // Physical address of connection peer
    phys_address: SocketAddr,

    // Packet stats
    recved: u64,
    sent: u64,
    lost: u64,

    // Handshake progress
    initial_keyset_generated: bool,
    handshake_done: bool,
    handshake_done_sent: bool,
    handshake_done_ackd: bool,

    initial_keyset: Option<Keys>,
}

impl Connection {
    pub fn new() -> Self {
        Connection {
            tls_session: None,
            next_secrets: None,
            handshake_data_received: false,
            scids: Vec::new(),
            dcids: Vec::new(),
            fdcid: vec![0, 0, 0, 0].into(),
            rscid: None,
            next_packet_num: 1,
            phys_address: SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                1234,
            ),
            recved: 0,
            sent: 0,
            lost: 0,
            initial_keyset_generated: false,
            handshake_done: false,
            handshake_done_sent: false,
            handshake_done_ackd: false,
            initial_keyset: None,
        }
    }

    pub fn recv(&mut self) -> Result<(), quic_error::Error> {
        Ok(())
    }

    pub fn accept() -> Result<(), quic_error::Error> {
        Ok(())
    }

    pub fn _send() {}
}

struct Header {
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

    //header length in bytes
    length: usize,
}

impl Header {
    pub fn decrypt(
        &mut self,
        b: &mut octets::OctetsMut,
        header_key: HeaderProtectionKey,
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
                hf: hf,
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
            hf: hf,
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
struct ConnectionId {
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
