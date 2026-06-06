pub mod connection;
pub mod terror;

mod cc;
mod cid;
mod fc;
mod io;
mod path;
mod ranges;
mod packet;
mod stream;
mod token;
mod transport_parameters;

use crate::{
    ranges::RangeSet,
    path::Paths
};
use octets::{varint_len, OctetsMut};
use packet::{AckFrame, Header};
use rustls::{
    quic::{
        Connection as RustlsConnection, DirectionalKeys, KeyChange, Keys, PacketKeySet, Version,
    },
    Side,
};
use rand::Rng;
use std::{collections::VecDeque, net::SocketAddr, sync::Arc, time::Instant};
use stream::{StreamManager, StreamManagerConfig};
use token::StatelessResetToken;
use tracing::{debug, error, event, span, warn, Level};
use transport_parameters::{
    ActiveConnectionIdLimit, InitialSourceConnectionId, MaxUdpPayloadSize,
    OriginalDestinationConnectionId, StatelessResetTokenTP, TransportConfig, VarInt,
};

const SPACE_ID_INITIAL: usize = 0x00;
const SPACE_ID_HANDSHAKE: usize = 0x01;
const SPACE_ID_DATA: usize = 0x02;

const MAX_PATHS: usize = 4;

enum QuicConfig {
    Server(Arc<rustls::ServerConfig>),
    Client(Arc<rustls::ClientConfig>),
}

impl QuicConfig {
    fn crypto_provider(&self) -> &rustls::crypto::CryptoProvider {
        match self {
            QuicConfig::Server(cfg) => cfg.crypto_provider(),
            QuicConfig::Client(cfg) => cfg.crypto_provider(),
        }
    }
}

// TODO pull out a CryptoProvider or something so a) its exchangeable and b) i can test things like
// fetch_dgram and so on
struct Inner {
    // side
    side: Side,

    // quic version
    version: u32,

    // pollable events
    events: Vec<InnerEvent>,

    // hmac key as input to stateless_reset_token generation
    hmac_reset_token_key: ring::hmac::Key,

    // tls13 session via rustls and keying material
    tls_session: RustlsConnection,
    next_secrets: Option<rustls::quic::Secrets>,
    next_1rtt_packet_keys: Option<PacketKeySet>,
    zero_rtt_keyset: Option<DirectionalKeys>,

    // connection state
    state: ConnectionState,

    // connection id manager
    cidm: cid::ConnectionIdManager,

    // stream manager, does all stream logic
    sm: StreamManager<stream::StreamWaker>,

    // Packet number spaces, inital, handshake, 1-RTT
    packet_spaces: [PacketNumberSpace; 3],
    current_space: usize,

    /// holds all paths of the connection and per path congestion control
    paths: Paths,

    // TransportConfig of remote
    remote_tpc: Option<TransportConfig>,

    // application error code
    apec: Option<u64>,

    // protocol error code, possible frame type
    pec: Option<(u64, u64)>,

    // tracks the last processed frame type in case of a protocol error
    lft: u64,

    // 0-Rtt enabled
    zero_rtt_enabled: bool,
}

impl Inner {
    fn get_current_path(&self) -> SocketAddr {
        self.paths.active().peer_addr
    }

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

    // TODO add idle-timeout / ack-delay
    /// next deadline this connection needs servicing: loss detection
    pub fn timeout(&self) -> Option<Instant> {
        self.paths.next_timeout()
    }

    /// service whatever fired
    fn handle_timeout(&mut self, now: Instant) {
        if let path::PathEvent::NoViablePath = self.paths.on_timeout(now) {
            self.apec = Some(terror::QuicTransportError::NoViablePath as u64);
            self.state = ConnectionState::Closing;
        }
        let _lost = self.paths.active_mut().on_loss_detection_timeout(now);
        // _lost / a pending PTO probe get sent on the next fetch_dgram
    }

    /// accepts a new initial packet
    fn accept(
        buffer: &mut Vec<u8>,
        src_addr: SocketAddr,
        local_addr: SocketAddr,
        server_config: Arc<rustls::ServerConfig>,
        hmac_reset_key: &ring::hmac::Key,
    ) -> Result<(Self, cid::Id), terror::Error> {
        let start = Instant::now();

        let mut head = packet::Header::from_bytes(buffer, 8).map_err(|e| {
            terror::Error::buffer_size_error(format!(
                "error decoding header from initial packet: {}",
                e
            ))
        })?;

        // get initial keys, use default crypto provider by ring with all suites for now
        let ikp = Self::derive_initial_keyset(
            QuicConfig::Server(server_config.clone()),
            Version::V1,
            Side::Server,
            &head.dcid,
        );

        let header_length = match head.decrypt(buffer, ikp.remote.header.as_ref()) {
            Ok(s) => s,
            Err(error) => panic!("Error: {}", error),
        };

        let mut b = OctetsMut::with_slice(buffer);
        let (header_raw, mut payload_cipher) = b.split_at(header_length).unwrap();

        // cut off trailing 0s from buffer, substract 1 extra beacuse packet num length of 1 is
        // encoded as 0...
        let (mut payload_cipher, _) = payload_cipher
            .split_at(head.length - head.packet_num_length as usize - 1)
            .unwrap();

        // payload cipher must be exact size without zeros from the buffer beeing to big!
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

        // truncate payload is possible because as a server the initial packet from a client cant be
        // coalesced
        buffer.truncate(dec_len);

        let mut p = Paths::new(local_addr, src_addr, true, MAX_PATHS);
        p.active_mut().on_datagram_received(buffer.len(), start);

        let (cim, initial_scid, srt) =
            cid::ConnectionIdManager::as_server(head.scid.unwrap(), head.dcid, 4, hmac_reset_key);

        let mut tpc = TransportConfig {
            original_destination_connection_id: OriginalDestinationConnectionId::try_from(
                head.dcid,
            )?,
            initial_source_connection_id: InitialSourceConnectionId::try_from(initial_scid)?,
            stateless_reset_token: StatelessResetTokenTP::try_from(srt)?,
            max_udp_payload_size: MaxUdpPayloadSize::try_from(VarInt::from(1472))?,
            active_connection_id_limit: ActiveConnectionIdLimit::try_from(VarInt::from(4))?,
            ..TransportConfig::default()
        };

        let smc = StreamManagerConfig::new(1, 0);

        let mut sm = StreamManager::new(smc, Side::Server as u8);
        sm.fill_initial_local_tpc(&mut tpc)?;

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

        let mut inner = Self {
            side: Side::Server,
            version: head.version,
            events: Vec::new(),
            hmac_reset_token_key: hmac_reset_key.clone(),
            tls_session: conn,
            next_secrets: None,
            next_1rtt_packet_keys: None,
            zero_rtt_keyset: None,
            state: ConnectionState::Initial,
            cidm: cim,
            sm,
            packet_spaces: [
                initial_space,
                PacketNumberSpace::new(),
                PacketNumberSpace::new(),
            ],
            current_space: SPACE_ID_INITIAL,
            paths: p,
            remote_tpc: None,
            apec: None,
            pec: None,
            lft: 0x00,
            zero_rtt_enabled: false,
        };

        // process inital packet explicitly to reduce state keeping
        // no need to check the error type, as the connection is discarded in case of an error
        inner.process_initial_packet(&head, buffer,0, start)?;

        // initial packet processing time
        let _m = start.elapsed().as_millis();

        Ok((inner, initial_scid))
    }

    /// creates a connection as a client with a destination
    pub fn connect(
        dst_addr: SocketAddr,
        local_addr: SocketAddr,
        server_name: rustls::pki_types::ServerName<'static>,
        client_config: Arc<rustls::ClientConfig>,
        hmac_reset_key: &ring::hmac::Key,
    ) -> Result<(Self, cid::Id), terror::Error> {
        let mut p = Paths::new(local_addr, dst_addr, false, MAX_PATHS);
        p.active_mut().mark_validated();

        let (cim, dcid, scid) = cid::ConnectionIdManager::as_client(4);

        let mut tpc = TransportConfig {
            original_destination_connection_id: OriginalDestinationConnectionId::try_from(dcid)?,
            initial_source_connection_id: InitialSourceConnectionId::try_from(scid)?,
            stateless_reset_token: StatelessResetTokenTP::try_from(
                token::StatelessResetToken::new(hmac_reset_key, &scid),
            )?,
            max_udp_payload_size: MaxUdpPayloadSize::try_from(VarInt::from(1472))?,
            active_connection_id_limit: ActiveConnectionIdLimit::try_from(VarInt::from(4))?,
            ..TransportConfig::default()
        };

        let smc = StreamManagerConfig::new(1, 0);

        let mut sm = StreamManager::new(smc, Side::Client as u8);
        sm.fill_initial_local_tpc(&mut tpc)?;

        let data = tpc.encode(Side::Server)?;

        let conn = RustlsConnection::Client(
            rustls::quic::ClientConnection::new(
                client_config.clone(),
                rustls::quic::Version::V1,
                server_name,
                data,
            )
            .map_err(|e| {
                terror::Error::fatal(format!("failed to create client connection: {}", e))
            })?,
        );

        let ikp = Self::derive_initial_keyset(
            QuicConfig::Client(client_config),
            Version::V1,
            Side::Client,
            &dcid,
        );

        let initial_space: PacketNumberSpace = PacketNumberSpace {
            keys: Some(ikp),
            active: true,
            ..PacketNumberSpace::new()
        };

        let mut inner = Self {
            side: Side::Client,
            version: 1u32,
            events: Vec::new(),
            hmac_reset_token_key: hmac_reset_key.clone(),
            tls_session: conn,
            next_secrets: None,
            next_1rtt_packet_keys: None,
            zero_rtt_keyset: None,
            state: ConnectionState::Initial,
            cidm: cim,
            sm,
            packet_spaces: [
                initial_space,
                PacketNumberSpace::new(),
                PacketNumberSpace::new(),
            ],
            current_space: SPACE_ID_INITIAL,
            paths: p,
            remote_tpc: None,
            apec: None,
            pec: None,
            lft: 0x00,
            zero_rtt_enabled: false,
        };

        inner.generate_crypto_data();

        Ok((inner, scid))
    }

    fn derive_initial_keyset(
        config: QuicConfig,
        version: Version,
        side: Side,
        dcid: &cid::Id,
    ) -> Keys {
        /* for now only the rustls ring provider is used, so we may omit numerous checks */
        config
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
            .keys(dcid.as_slice(), side, version)
    }

    fn recv(
        &mut self,
        buffer: &mut [u8],
        partial_decode: &mut Header,
        src_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> Result<(), terror::Error> {
        // in theory that should no happen
        if self.state == ConnectionState::Closing || self.state == ConnectionState::Closed {
            return Err(terror::Error::fatal(
                "cannot recv packet on closed or closing connection",
            ));
        }

        // do path stuff
        let pid = match self.paths.index_of(local_addr, src_addr) {
            Some(i) => i,
            None => {
                let i = self
                    .paths
                    .add_path(local_addr, src_addr)
                    .ok_or_else(|| terror::Error::fatal("path limit reached"))?;
                // peer is using a new address: validate it before relying on it (§9)
                if self.state == ConnectionState::Connected {
                    self.paths.get_mut(i).unwrap().request_validation();
                }
               i
            }
        };

        // anti-amplification accounting is per datagram, not per coalesced packet (§8)
        self.paths
            .get_mut(pid)
            .unwrap()
            .on_datagram_received(buffer.len(), Instant::now());

        // process the first packet
        let mut offset = self.recv_single(buffer, partial_decode, pid).inspect_err(|e| {
            // Check if we encountered a quic protocol error
            if (0x01..=0x10).contains(&e.kind()) {
                self.pec = Some((e.kind(), self.lft));
                self.state = ConnectionState::Closing;
            }
        })?;
        let mut remaining: usize = buffer.len() - offset;

        debug!("processed packet with {} bytes", offset);

        let mut packet_type = partial_decode.hf >> 7;

        // while the last decoded packet is not a short packet, try and decode coalesced packets
        while packet_type != 0 && remaining > 0 {
            let mut partial_decode = packet::Header::from_bytes(&buffer[offset..], 8)?;

            debug!("I {}", &partial_decode);

            packet_type = partial_decode.hf >> 7;
            let processed_bytes = self
                .recv_single(&mut buffer[offset..], &mut partial_decode, pid)
                .inspect_err(|e| {
                    // Check if we encountered a quic protocol error
                    if (0x01..=0x10).contains(&e.kind()) {
                        self.pec = Some((e.kind(), self.lft));
                        self.state = ConnectionState::Closing;
                    }
                })?;

            debug!("processed packet with {} bytes", processed_bytes);

            offset += processed_bytes;
            remaining -= processed_bytes;
        }

        Ok(())
    }

    #[tracing::instrument(skip_all, fields(space = header.space()))]
    fn recv_single(
        &mut self,
        packet: &mut [u8],
        header: &mut Header,
        path: usize,
    ) -> Result<usize, terror::Error> {
        let start = Instant::now();
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

        // if client and packet is initial from server, update cid
        if self.side == Side::Client && header.space() == SPACE_ID_INITIAL {
            self.cidm.replace_initial_dcid(header.scid.unwrap());
        }

        // decrypt packet
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

        // rfc 9000 sec 12.2: Retry packets, Version Negotiation packets, and packets with a
        // short header do not contain a Length field and so cannot be followed by other
        // packets in the same UDP datagram
        // Therefore we only need to trim payload_cipher if we have an initial, handshake or
        // zero rtt packet
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

        // TODO path handling here after decryption

        self.process_payload(header, &mut payload, path, start)?;

        // calucate ema
        let _ppt = start.elapsed().as_nanos();

        Ok(raw_packet_length)
    }

    // accepts new connection
    fn process_initial_packet(
        &mut self,
        header: &Header,
        packet_raw: &mut [u8],
        path: usize,
        now: Instant,
    ) -> Result<(), terror::Error> {
        let mut payload = octets::OctetsMut::with_slice(packet_raw);

        // skip forth to packet payload
        payload.skip(header.raw_length + header.packet_num_length as usize + 1)?;

        self.process_payload(header, &mut payload,path, now)?;

        // init zero rtt if enabled
        if self.zero_rtt_enabled {
            if let Some(zero_rtt_keyset) = self.tls_session.zero_rtt_keys() {
                self.zero_rtt_keyset = Some(zero_rtt_keyset);
            } else {
                error!("failed to derive zero rtt keyset");
            }
        }

        self.state = ConnectionState::Handshake;

        Ok(())
    }

    // processes a packets payload. Takes the header of the packet and an OctetsMut object of the
    // payload starting after the packet number and ending with the last byte of this packets
    // payload. It must not include another packets header or payload.
    #[tracing::instrument(skip_all, fields(pn = header.packet_num))]
    fn process_payload(
        &mut self,
        header: &Header,
        payload: &mut OctetsMut,
        path: usize,
        now: Instant,
    ) -> Result<(), terror::Error> {
        let mut ack_eliciting = false;
        let mut non_probing = false;

        while payload.peek_u8().is_ok() {
            let frame_code = payload.get_u8().unwrap();
            self.lft = frame_code as u64;

            //check if frame is ack eliciting
            match frame_code {
                0x00 | 0x02 | 0x03 | 0x1c | 0x1d => (),
                _ => ack_eliciting = true,
            }

            match frame_code {
                0x00 | 0x18 | 0x1a | 0x1b => {}
                _ => non_probing = true,
            }

            match frame_code {
                0x00 => {
                    // the first received padding indicates that the rest of the packet is also
                    // padded and can therefore be skipped
                    payload.skip(payload.cap())?;
                    break;
                } //PADDING
                0x01 => {} //PING
                0x02 | 0x03 => {
                    let ack = AckFrame::parse(&frame_code, payload);
                    self.process_ack(&ack, header.space(), path, now)?;
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

                    self.process_crypto_data(&crypto_data)?;

                    // test if all required crypto data has been exchanged for the connection to be
                    // considered established
                    if self.tls_session.alpn_protocol().is_some()
                        && self.tls_session.negotiated_cipher_suite().is_some()
                        && !self.tls_session.is_handshaking()
                        && self.state == ConnectionState::Handshake
                    {
                        event!(
                            Level::INFO,
                            "connection established to {}",
                            self.paths.active().peer_addr
                        );

                        self.paths.active_mut().cc_mut().confirm_handshake();
                        self.paths.active_mut().mark_validated();

                        self.state = ConnectionState::Connected;
                        self.events.push(InnerEvent::ConnectionEstablished);
                    }

                    self.generate_crypto_data();
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
                    let max_data = payload.get_varint()?;

                    self.sm.set_max_data(max_data);

                    debug!("set max_data to {max_data}");
                } //MAX_DATA
                0x11 => {
                    let stream_id = payload.get_varint()?;
                    let max_data = payload.get_varint()?;

                    self.sm.set_max_stream_data(max_data, stream_id)?;

                    debug!("set max_stream_data of {stream_id} to {max_data}");
                } //MAX_STREAM_DATA
                0x12 => {
                    let max_streams = payload.get_varint()?;

                    self.sm.set_max_streams_bidi(max_streams);

                    debug!("set max bidi streams to {max_streams}");
                } //MAX_STREAMS (bidirectional)
                0x13 => {
                    let max_streams = payload.get_varint()?;

                    self.sm.set_max_streams_uni(max_streams);

                    debug!("set max uni streams to {max_streams}");
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
                    let rpt = payload.get_varint()?;
                    let l = payload.get_u8().unwrap();

                    if (l as usize > cid::MAX_CID_SIZE) || ((l as usize) < 1usize) {
                        return Err(terror::Error::quic_transport_error(
                            "received cid exceeds maximum cid size",
                            terror::QuicTransportError::ProtocolViolation,
                        ));
                    }

                    let n_cid = cid::Id::from(payload.get_bytes(l as usize)?.to_vec());
                    let srt = StatelessResetToken::from(payload.get_bytes(0x10)?.to_vec());

                    debug!(
                        "received new cid from peer: {} (sqn: {}, rpt: {})",
                        n_cid, sqn, rpt
                    );

                    self.cidm.handle_new_cid(sqn, rpt, n_cid, srt)?;
                } //NEW_CONNECTION_ID
                0x19 => {
                    let sqn = payload.get_varint()?;
                    self.events.push(InnerEvent::RetireConnectionId(
                        self.cidm.handle_retire_cid(sqn)?,
                    ));
                } //RETIRE_CONNECTION_ID
                0x1a => {
                    let data = payload.get_u64()?.to_be_bytes();
                    if let Some(p) = self.paths.get_mut(path) {
                        p.on_path_challenge(data);
                    }
                } //PATH_CHALLENGE
                0x1b => {
                    let data = payload.get_u64()?.to_be_bytes();
                    let _r = self.paths.on_path_response(data);
                } //PATH_RESPONSE
                0x1c | 0x1d => {
                    let ec = payload.get_varint()?;
                    let efc = if frame_code == 0x1c {
                        payload.get_varint()?
                    } else {
                        0
                    };

                    let rp = std::str::from_utf8(payload.get_bytes_with_varint_length()?.buf())
                        .unwrap_or("");

                    self.events.push(InnerEvent::ClosedByPeer);
                    self.state = ConnectionState::Closed;

                    error!("connection closed by peer. error code {ec}, error frame {efc}, reason: {rp}");

                    // TODO reset all streams
                } // CONNECTION_CLOSE_FRAME
                0x1e => {
                    if self.side == Side::Server {
                        return Err(terror::Error::quic_transport_error(
                            "received HANDSHAKE_DONE frame as server",
                            terror::QuicTransportError::ProtocolViolation,
                        ));
                    }
                } // HANDSHAKE_DONE
                _ => warn!(
                    "Error while processing frames: unrecognised frame {:#x} at {:#x}",
                    frame_code,
                    payload.off()
                ),
            }
        }

        // connection migration: a non-probing 1-RTT packet from a non-active
        // path that is the newest we've seen means the peer moved. Switch our send
        // path to it and validate concurrently; anti-amplification + the fresh per-path
        // cc keep us correct on the new path until it validates
        if header.space() == SPACE_ID_DATA
            && self.state == ConnectionState::Connected
            && non_probing
            && path != self.paths.active_idx()
            && self.packet_spaces[header.space()]
                .received_pns
                .largest().unwrap_or(0) < header.packet_num
        {
            debug!(
                "peer migrated to {}, switching active path",
                self.paths.get(path).unwrap().peer_addr
            );
            self.paths.migrate_to(path);
            if !self.paths.get(path).unwrap().is_validated() {
                self.paths.get_mut(path).unwrap().request_validation();
            }
        }

        self.packet_spaces[header.space()]
            .received_pns
            .push(header.packet_num);

        if ack_eliciting {
            self.packet_spaces[header.space()].ack_eliciting_received = true;
        }

        // if we get to here, no error occured and if a protocol error occurs, no frame is the
        // culprit
        self.lft = 0x00;

        Ok(())
    }

    fn process_ack(&mut self, ack: &AckFrame, space: usize, path: usize, now: Instant) -> Result<(), terror::Error> {
        let (acked_pns, lost_pns) = match self.paths.get_mut(path) {
            Some(p) => p.on_ack_received(space, ack, now),
            None => return Ok(()),
        };

        debug!(count = acked_pns.len(), space, "processing ACK frame");

        self.sm.ack(&acked_pns);
        self.cidm.ack(&acked_pns);

        // TODO also decide what frames to track with what data
        // TODO add tracking to what we sent. if we get an ack for a packet in which we sent an ack
        // we excute:
        // self.packet_spaces[space].received_pns.remove_until(largest_acked_by_that_packet);
        // maybe even let on_ack_received return an owning vector to the frames

        if !lost_pns.is_empty() {
            warn!(count = lost_pns.len(), space, "packets declared lost after ACK");
            // TODO: mark frames carried by lost_pns for retransmission
        }

        Ok(())
    }

    fn process_crypto_data(&mut self, crypto_data: &[u8]) -> Result<(), terror::Error> {
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

        if self.remote_tpc.is_none() {
            if let Some(raw) = self.tls_session.quic_transport_parameters() {

                match TransportConfig::decode(raw) {
                    Ok(tpc) => self.remote_tpc = Some(tpc),
                    Err(e) => {
                        return Err(e);
                    }
                }

                let rtpc = self.remote_tpc.as_ref().unwrap();

                // register stream limits in stream manager
                let (imd, imsdbl, imsdbr, imsdu, imsb, imsu) = rtpc.get_initial_limits();

                self.sm.set_initial_data_limits(imsdbl, imsdbr, imsdu);
                self.sm.set_max_data(imd);
                self.sm.set_max_streams_bidi(imsb);
                self.sm.set_max_streams_uni(imsu);

                // the peers initial_source_connection_id should have been saved as our first dcid
                if rtpc.initial_source_connection_id.get() != self.cidm.get_dcid() {
                    return Err(terror::Error::quic_transport_error(
                        "scids from packet header and transport parameters differ",
                        terror::QuicTransportError::TransportParameterError,
                    ));
                }

                // set congestion control values
                //self.cc.set_ack_delay_exponent(rtpc.ack_delay_exponent);
                //self.cc.set_max_ack_delay(std::time::Duration::from_millis(rtpc.max_ack_delay.get().get()));
                self.paths.active_mut().cc_mut().set_ack_delay_exponent(rtpc.ack_delay_exponent);
                self.paths.active_mut().cc_mut().set_max_ack_delay(
                    std::time::Duration::from_millis(rtpc.max_ack_delay.get().get()),
                );
            }
        }

        Ok(())
    }

    fn generate_crypto_data(&mut self) {
        loop {
            let mut buf: Vec<u8> = Vec::new();

            if let Some(kc) = self.tls_session.write_hs(&mut buf) {
                let (keys, next_space) = match kc {
                    KeyChange::Handshake { keys } => {
                        debug!("handshake keyset ready");
                        self.packet_spaces[SPACE_ID_HANDSHAKE].active = true;
                        (keys, SPACE_ID_HANDSHAKE)
                    }
                    KeyChange::OneRtt { keys, next } => {
                        debug!("data (1-rtt) keyset ready");
                        self.next_secrets = Some(next);
                        self.packet_spaces[SPACE_ID_DATA].active = true;

                        if (self.current_space + 1) == SPACE_ID_DATA {
                            self.next_1rtt_packet_keys = Some(
                                self.next_secrets
                                    .as_mut()
                                    .expect("hs should be completed and next secrets available")
                                    .next_packet_keys(),
                            );
                        }

                        (keys, SPACE_ID_DATA)
                    }
                };

                self.packet_spaces[next_space].keys = Some(keys);
                self.current_space = next_space;
            }

            if !buf.is_empty() {
                debug!(
                    "generated {} bytes of crypto data in space {}",
                    buf.len(),
                    self.current_space
                );

                let offset = self.packet_spaces[self.current_space].outgoing_crypto_offset;
                let length = buf.len() as u64;

                self.packet_spaces[self.current_space]
                    .outgoing_crypto
                    .push_back((offset, buf));
                self.packet_spaces[self.current_space].outgoing_crypto_offset += length;

                continue;
            }

            break;
        }
    }

    fn fetch_dgram(&mut self, buffer: &mut [u8]) -> Result<usize, terror::Error> {
        if self.state == ConnectionState::Closed {
            return Err(terror::Error::fatal(
                "cannot fetch packet from closed connection",
            ));
        }

        let cwnd = self.paths.active().cwnd_available();
        let budget = self.paths.active().send_budget();
        let max_payload_size = self
            .remote_tpc
            .as_ref()
            .map(|t| t.max_udp_payload_size.get().get() as usize)
            .unwrap_or(1200);
        let mut remaining = buffer.len().min(cwnd).min(budget).min(max_payload_size);
        debug!("remaining: {}", remaining);

        let mut written: usize = 0;

        let mut contains_initial = false;
        let mut encoded_packets: usize = 0;

        let mut ack_eliciting = false;

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
                // either we're done or we need to throw an error
                if encoded_packets == 0 {
                    return Err(terror::Error::no_data("no data to send"));
                } else {
                    return Ok(written);
                }
            }

            debug!("building {} packet", packet_type);
            debug!("remaining space {}", remaining);

            let now = Instant::now();
            let pn = self.packet_spaces[space_id].get_next_pkt_num();
            let dcid = self.cidm.get_dcid();

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

                    let scid = self.cidm.get_scid();

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

            let aead_tag_len = keys.packet.tag_len();

            let packet_size_overhead =
                header.raw_length + header.packet_num_length as usize + 1 + aead_tag_len;

            debug!("packet_size_overhead: {}", packet_size_overhead);

            // check if size overhead for packet fits in rest
            if packet_size_overhead > remaining {
                // either we're done or we need to throw an error
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

            // encode header and keep track of where the length field has been encoded
            let mut header_length_offset: usize = 0;
            header.to_bytes(&mut buf, &mut header_length_offset)?;

            let mut path_challenge_sent: Option<[u8; 8]> = None;

            //println!("after header encoding: {:x?}", &buf.buf()[..buf.off()]);

            let payload_offset = buf.off();

            //debug!("payload_offset: {}", payload_offset);

            assert!(
                header.raw_length + header.packet_num_length as usize + 1 == buf.off(),
                "header end offset does not match"
            );

            // handle possible error
            let is_closing = if self.state == ConnectionState::Closing {
                match packet_type {
                    packet::PacketType::None | packet::PacketType::Retry => false,
                    _ => {
                        if let Some((ec, ef)) = self.pec {
                            buf.put_varint(0x1c)?;
                            buf.put_varint(ec)?;
                            buf.put_varint(ef)?;
                            buf.put_varint(0x00)?;

                            warn!("encoded error 0x1c {ec} {ef}");
                        } else if let Some(ec) = self.apec {
                            match packet_type {
                                packet::PacketType::Short | packet::PacketType::ZeroRtt => {
                                    buf.put_varint(0x1d)?;
                                    buf.put_varint(ec)?;
                                    buf.put_varint(0x00)?;

                                    warn!("encoded error 0x1d {ec}");
                                }
                                packet::PacketType::Initial | packet::PacketType::Handshake => {
                                    // in case an application error is being raised while still
                                    // handshaking, encode as quic application error. should not happen
                                    buf.put_varint(0x1c)?;
                                    buf.put_varint(
                                        terror::QuicTransportError::ApplicationError as u64,
                                    )?;
                                    buf.put_varint(0x00)?;
                                    buf.put_varint(0x00)?;

                                    warn!("encoded error 0x1c (app) {ec} 0x00");
                                }
                                _ => {}
                            }
                        }
                        true
                    }
                }
            } else {
                false
            };

            // fill that packet with data
            // ack frames
            if self.packet_spaces[space_id].ack_eliciting_received && !is_closing {
                const LOCAL_ACK_DELAY_EXPONENT: u32 = 3;
                let ack_delay = self.packet_spaces[space_id]
                    .latest_ack_recv_time
                    .map(|t| now.duration_since(t).as_micros() as u64 >> LOCAL_ACK_DELAY_EXPONENT)
                    .unwrap_or(0);

                //debug!(space = space_id, count = self.packet_spaces[space_id].received_pns.len(),
                //    ack_delay, "encoding ACK frame");

                // directly generate ack frame from packet number vector

                // TODO there is a bug here. If frame was too small, directly passing the octets buf
                // still advances it, effectively writing a corrupted frame

                let _ = AckFrame::to_bytes( // TODO decide if we want to do something with the error
                    &self.packet_spaces[space_id].received_pns,
                    None, // TODO figure out
                    ack_delay,
                    &mut buf,
                );

                //clear vector as packet numbers are now ack'ed
                self.packet_spaces[space_id].latest_ack_recv_time = None;
                self.packet_spaces[space_id].ack_eliciting_received = false
            };

            // clear queued crypto frames in case the connection is beeing closed
            if is_closing {
                self.packet_spaces[space_id].outgoing_crypto.clear();
            }

            // crypto frames
            while let Some((off, data)) = self.packet_spaces[space_id].outgoing_crypto.front() {
                let enc_len = 1 + varint_len(*off) + varint_len(data.len() as u64) + data.len();

                if buf.cap() >= enc_len {
                    debug!("CRYPTO frame: off {} len {}", off, data.len());
                    println!("CRYPTO frame: off {} len {}", off, data.len());

                    buf.put_u8(0x06)?;
                    buf.put_varint(*off)?;
                    buf.put_varint(data.len() as u64)?;
                    buf.put_bytes(data)?;

                    self.packet_spaces[space_id].outgoing_crypto.pop_front();

                    ack_eliciting = true;
                } else {
                    warn!("not enough space left to encode crypto frame with len {enc_len}");
                }
            }

            // stream & cid frames
            if packet_type == packet::PacketType::Short && !is_closing {
                // PATH_RESPONSE, echo any received challenges first
                while buf.cap() >= 9 {
                    match self.paths.active_mut().poll_response() {
                        Some(data) => {
                            buf.put_u8(0x1b)?;
                            buf.put_u64(u64::from_be_bytes(data))?;
                            ack_eliciting = true;
                        }
                        None => break,
                    }
                }

                // PATH_CHALLENGE, emit one if the active path wants validating
                if self.paths.active().probing_required() && buf.cap() >= 9 {
                    let mut b = [0u8; 8];
                    rand::rng().fill_bytes(&mut b);
                    buf.put_u8(0x1a)?;
                    buf.put_u64(u64::from_be_bytes(b))?;
                    ack_eliciting = true;
                    path_challenge_sent = Some(b);
                }

                // NEW_CONNECTION_ID frame
                // calc size for frame, rpt must be smaller than sqn, frame header, id, srt
                if buf.cap() >= (1 + (2 * varint_len(self.cidm.peek_next_sqn() as u64)) + 8 + 16) {
                    if let Some((sqn, rpt, id, srt)) =
                        self.cidm.issue_new_cid(&self.hmac_reset_token_key, pn)
                    {
                        // check if buf has enough space left
                        buf.put_u8(0x18)?;
                        buf.put_varint(sqn)?;
                        buf.put_varint(rpt)?;
                        buf.put_u8(0x08)?;
                        buf.put_bytes(id.as_slice())?;
                        buf.put_bytes(&srt.token)?;

                        self.events.push(InnerEvent::NewConnectionId(id));

                        ack_eliciting = true;
                    }
                }

                // RETIRE_CONNECTION_ID frames
                let next_sqn_retirement = self.cidm.peek_next_pending_cid_retirement();
                if next_sqn_retirement > 0 && buf.cap() >= next_sqn_retirement {
                    buf.put_u8(0x19)?;
                    buf.put_varint(self.cidm.pop_next_pending_cid_retirement(pn))?;
                    ack_eliciting = true;
                }

                // create STREAMS_BLOCKED if bidi streams are blocked
                if let Some(seq) = self.sm.bidi_streams_blocked() {
                    debug!("bidi streams blocked at {}", seq);
                    buf.put_varint(0x16)?;
                    buf.put_varint(seq)?;
                    ack_eliciting = true;
                }

                // create STREAMS_BLOCKED if uni streams are blocked
                if let Some(seq) = self.sm.uni_streams_blocked() {
                    debug!("uni streams blocked at {}", seq);
                    buf.put_varint(0x17)?;
                    buf.put_varint(seq)?;
                    ack_eliciting = true;
                }

                // create MAX_STREAM_DATA frames for connection
                self.sm.upgrade_max_stream_data(&mut buf)?;

                // create MAX_STREAMS to increase our recv stream limit
                self.sm.upgrade_peer_stream_limits(&mut buf)?;

                // create MAX_DATA for connection, buffer req: frame code (1) + max max_data (8)
                if self.sm.nearly_full()
                    && buf.cap()
                        >= 0x01 + varint_len(self.sm.max_data() + fc::MAX_WINDOW_CONNECTION)
                {
                    let n_md = self.sm.upgrade_max_data();

                    buf.put_varint(0x10)?;
                    buf.put_varint(n_md)?;
                    ack_eliciting = true;
                }

                // encode stream frame last to ensure enough room for flow control frames.
                // implicitly encodes DATA_BLOCKED, STREAM_DATA_BLOCKED
                let bytes = self.sm.emit_fill(buf.as_mut(), pn)?;
                buf.skip(bytes)?;
                if bytes > 0 { ack_eliciting = true; }

                // PTO probe: if a probe is required but no ack-eliciting frame has been
                // written yet, emit a PING. This satisfies the probe obligation without
                // any retransmission logic; probe_pending is cleared by on_packet_sent
                if self.paths.active().cc().probe_pending() && !ack_eliciting && buf.cap() >= 1 {
                    buf.put_u8(0x01)?; // PING
                    ack_eliciting = true;
                    debug!("emitting PING frame to satisfy PTO probe");
                }
            }

            // if is last packet, pad to min size of 1200
            if contains_initial
                && !self.packet_spaces[std::cmp::min(space_id + 1, SPACE_ID_DATA)].wants_write()
            {
                // if packet header is long, add padding length to length field, if it is short skip
                // padding length
                if (buf.off() + written + aead_tag_len) < 1200 {
                    let skip = std::cmp::max(1200 - buf.off() - written - aead_tag_len, 0);
                    debug!(
                        "datagram contains initial frame and this last packet is padded by: {}",
                        skip
                    );
                    buf.skip(skip)?;
                }
            }

            // if packet contains a path challenge, pad to 1200 bytes to confirm min mtu
            if path_challenge_sent.is_some() {
                let target = 1200usize.saturating_sub(written + aead_tag_len);
                if buf.off() < target {
                    let skip = (target - buf.off()).min(buf.cap());
                    buf.skip(skip)?;
                }
            }

            let payload_length = buf.off() - payload_offset;
            debug!("payload length: {}", payload_length);

            let length = payload_length + aead_tag_len + (header.packet_num_length as usize + 1);

            // determine length of packet and encode it
            if packet_type != packet::PacketType::Short {
                debug!("encoded length in header: {}", length);

                let (_, mut l) = buf.split_at(header_length_offset)?;
                l.put_varint_with_len(length as u64, packet::PACKET_LENGTH_ENCODING_LENGTH)?;
            }

            println!("PRE ENCRYPT: {:x?}", buf);

            // encrypt the packet
            let packet_length = packet::encrypt(&mut buf, keys, pn, payload_offset)?;

            debug!("packet_length: {}", packet_length);

            /*if ack_eliciting {
                self.cc.on_packet_sent(space_id, pn, packet_length, now);
            }*/
            self.paths
                .active_mut()
                .on_packet_sent(pn, space_id, packet_length, ack_eliciting, now);

            if let Some(data) = path_challenge_sent {
                // datagram_len = coalesced prefix + this packet; >= 1200 also validates the MTU
                self.paths
                    .active_mut()
                    .add_challenge_sent(data, written + packet_length, now);
            }

            encoded_packets += 1;
            remaining -= packet_length;
            written += packet_length;

            // short packets cannot be coalesced
            if packet_type == packet::PacketType::Short || is_closing {
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

    pub fn poll_events(&mut self) -> Vec<InnerEvent> {
        std::mem::take(&mut self.events)
    }
}

/// emitted after a packet is received. can be polled via [`Inner::poll_event(&mut self)`].
enum InnerEvent {
    // emitted once per connection when it is established and becomes available to the application.
    // emitted after incoming packet
    ConnectionEstablished,

    // emitted only when we (our side) issue a new connection id to out peer so that the io
    // implementation knows which connection ids to match to which connection. emitted after
    // outgoing packet
    NewConnectionId(cid::Id),

    // emitted we receive an RETIRE_CONNECTION_ID from our peer, indicating it wont use that id
    // anymore to address our endpoint. emitted after incoming packet
    RetireConnectionId(cid::Id),

    // emitted when the connection has been closed by the peer. emitted on imcoming packet
    ClosedByPeer,
}

#[derive(PartialEq)]
enum ConnectionState {
    Initial,
    Handshake,
    Connected,
    Closing,
    Closed,
}

//RFC 9000 section 12.3. we have 3 packet number spaces: initial, handshake & 1-RTT
struct PacketNumberSpace {
    keys: Option<Keys>,

    received_pns: RangeSet,

    // timestamp of the most recent ack-eliciting packet received in this space.
    // used to compute the ack delay field, the time between receiving the packet and
    // actually sending the ack
    latest_ack_recv_time: Option<Instant>,
    ack_eliciting_received: bool,

    outgoing_crypto: VecDeque<(u64, Vec<u8>)>,
    outgoing_crypto_offset: u64,

    next_pkt_num: u64,

    active: bool,
}

impl PacketNumberSpace {
    fn new() -> Self {
        Self {
            keys: None,
            received_pns: RangeSet::new(64),
            latest_ack_recv_time: None,
            ack_eliciting_received: false,
            outgoing_crypto: VecDeque::new(),
            outgoing_crypto_offset: 0,
            next_pkt_num: 0,
            active: false,
        }
    }

    //determines if a space has outgoing crypto data or acks
    fn wants_write(&self) -> bool {
        self.active && (self.ack_eliciting_received || !self.outgoing_crypto.is_empty())
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
