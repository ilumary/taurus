pub mod connection;
pub mod terror;

mod cc;
mod cid;
mod endpoint;
mod executor;
mod fc;
mod io;
mod packet;
mod path;
mod ranges;
mod stream;
mod token;
mod transport_parameters;

use crate::{path::Paths, ranges::RangeSet};
use octets::{varint_len, OctetsMut};
use packet::{AckFrame, Header};
use rand::Rng;
use rustls::{
    quic::{
        Connection as RustlsConnection, DirectionalKeys, KeyChange, Keys, PacketKeySet, Version,
    },
    Side,
};
use smallvec::SmallVec;
use std::{net::SocketAddr, sync::Arc, time::Instant};
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

// TODO pull out a CryptoProvider or something so all the crypto/tls stuff is separate
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
    sm: StreamManager,

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

    // server only, enqueues handshake done frame
    handshake_done_pending: bool,

    /// if set we're either in closing or draining and once it runs out we're closed
    close_deadline: Option<Instant>,

    /// wether we already sent a close frame. may be reset while already closing if a packet arrives
    /// after we sent a connection close frame
    close_sent: bool,
}

impl Inner {
    fn get_current_path(&self) -> SocketAddr {
        self.paths.active().peer_addr
    }

    fn stream_accept(&mut self, stream_t: u64) -> Option<u64> {
        if let Some(id) = self.sm.poll_ready(stream_t | ((self.side as u64) ^ 0x01)) {
            return Some(id);
        }

        None
    }

    fn stream_open(&mut self, stream_t: u64) -> Option<u64> {
        self.sm.initiate(stream_t, None)
    }

    fn stream_read(
        &mut self,
        stream_id: &u64,
        buf: &mut [u8],
    ) -> Result<Option<usize>, terror::Error> {
        self.sm.consume(stream_id, buf)
    }

    fn stream_write(
        &mut self,
        stream_id: u64,
        buf: &[u8],
        fin: bool,
    ) -> Result<usize, terror::Error> {
        self.sm.append(stream_id, buf, fin)
    }

    fn stream_finished(&self, stream_id: &u64) -> bool {
        !self.sm.has_send_stream(stream_id)
    }

    // TODO add idle-timeout / ack-delay
    /// next deadline this connection needs servicing: loss detection
    pub fn timeout(&self) -> Option<Instant> {
        if let Some(dl) = self.close_deadline {
            return Some(dl);
        }
        self.paths.next_timeout()
    }

    pub fn begin_close(&mut self, ec: u64, _reason: Option<&str>) {
        if self.state == ConnectionState::Closing || self.state == ConnectionState::Closed {
            return;
        }
        self.apec = Some(ec);
        self.state = ConnectionState::Closing;

        let now = Instant::now();
        self.close_deadline = Some(self.paths.active().close_timeout(now));

        tracing::trace!(now = ?now, close_deadline = ?self.close_deadline.unwrap(), "armed closing deadline");

        self.close_sent = false;
    }

    pub fn is_closing(&self) -> bool {
        self.state == ConnectionState::Closing || self.state == ConnectionState::Draining
    }

    pub fn is_closed(&self) -> bool {
        self.state == ConnectionState::Closed
    }

    /// service whatever fired
    fn handle_timeout(&mut self, now: Instant) {
        if let Some(dl) = self.close_deadline {
            if now >= dl {
                self.state = ConnectionState::Closed;
                tracing::trace!("closing deadline fired. connection is now closed");
                return;
            }
        }

        if let path::PathEvent::NoViablePath = self.paths.on_timeout(now) {
            self.apec = Some(terror::QuicTransportError::NoViablePath as u64);
            self.state = ConnectionState::Closing;
        }
        let _lost = self.paths.active_mut().on_loss_detection_timeout(now);
        // _lost / a pending PTO probe get sent on the next fetch_dgram
    }

    /// accepts a new initial packet
    fn accept(
        buffer: &mut [u8],
        src_addr: SocketAddr,
        local_addr: SocketAddr,
        server_config: Arc<rustls::ServerConfig>,
        hmac_reset_key: &ring::hmac::Key,
        _id: u8,
    ) -> Result<(Self, cid::Id), terror::Error> {
        let start = Instant::now();

        let mut head = packet::Header::from_bytes(buffer, 8).map_err(|e| {
            terror::Error::buffer_size_error(format!(
                "error decoding header from initial packet: {}",
                e
            ))
        })?;

        // get initial keys, use default crypto provider by ring with all suites for now
        let crypto_provider = server_config.crypto_provider().clone();
        let ikp =
            Self::derive_initial_keyset(&crypto_provider, Version::V1, Side::Server, &head.dcid);

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

        // truncate buffer
        let buffer = &mut buffer[..header_length + dec_len];

        let mut p = Paths::new(local_addr, src_addr, true, MAX_PATHS);
        p.active_mut().on_datagram_received(buffer.len(), start);

        let (cim, initial_scid, srt) =
            cid::ConnectionIdManager::as_server(head.scid.unwrap(), head.dcid, 4, hmac_reset_key);

        let mut tpc = TransportConfig {
            original_destination_connection_id: Some(OriginalDestinationConnectionId::try_from(
                head.dcid,
            )?),
            initial_source_connection_id: Some(InitialSourceConnectionId::try_from(initial_scid)?),
            stateless_reset_token: Some(StatelessResetTokenTP::try_from(srt)?),
            max_udp_payload_size: MaxUdpPayloadSize::try_from(VarInt::from(1472))?,
            active_connection_id_limit: ActiveConnectionIdLimit::try_from(VarInt::from(4))?,
            // TODO retry_source_connection_id, preferred_address
            ..TransportConfig::default()
        };

        let smc = StreamManagerConfig::new(2, 2, 1024 * 1024);

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
            handshake_done_pending: false,
            close_deadline: None,
            close_sent: false,
        };

        // process inital packet explicitly to reduce state keeping
        // no need to check the error type, as the connection is discarded in case of an error
        inner.process_initial_packet(&head, buffer, 0, start)?;

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
        _id: u8,
    ) -> Result<(Self, cid::Id), terror::Error> {
        let mut p = Paths::new(local_addr, dst_addr, false, MAX_PATHS);
        p.active_mut().mark_validated();

        let (cim, dcid, scid) = cid::ConnectionIdManager::as_client(4);

        let mut tpc = TransportConfig {
            original_destination_connection_id: None, // server-only; never set on a client
            initial_source_connection_id: Some(InitialSourceConnectionId::try_from(scid)?),
            max_udp_payload_size: MaxUdpPayloadSize::try_from(VarInt::from(1472))?,
            active_connection_id_limit: ActiveConnectionIdLimit::try_from(VarInt::from(4))?,
            ..TransportConfig::default()
        };

        let smc = StreamManagerConfig::new(2, 2, 1024 * 1024);

        let mut sm = StreamManager::new(smc, Side::Client as u8);
        sm.fill_initial_local_tpc(&mut tpc)?;

        let data = tpc.encode(Side::Client)?;

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

        let crypto_provider = client_config.crypto_provider().clone();
        let ikp = Self::derive_initial_keyset(&crypto_provider, Version::V1, Side::Client, &dcid);

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
            handshake_done_pending: false,
            close_deadline: None,
            close_sent: false,
        };

        inner.generate_crypto_data();

        debug!(
            "post-connect: initial wants_write={}",
            inner.packet_spaces[SPACE_ID_INITIAL]
                .crypto_tx
                .wants_write()
        );

        Ok((inner, scid))
    }

    fn derive_initial_keyset(
        crypto_provider: &rustls::crypto::CryptoProvider,
        version: Version,
        side: Side,
        dcid: &cid::Id,
    ) -> Keys {
        /* for now only the rustls ring provider is used, so we may omit numerous checks */
        crypto_provider
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
        src_addr: SocketAddr,
        local_addr: SocketAddr,
        _ecn: u8,
    ) -> Result<(), terror::Error> {
        if self.is_closed() || self.state == ConnectionState::Draining {
            tracing::error!("cannot recv packet on closed connection");
            return Ok(());
        }

        if self.state == ConnectionState::Closing {
            // we closed the connection so packets may still arrive, we anwser with closed again
            self.close_sent = false;
            return Ok(());
        }

        // do path stuff
        let pid = match self.paths.index_of(local_addr, src_addr) {
            Some(i) => i,
            None => {
                let i = self
                    .paths
                    .add_path(local_addr, src_addr)
                    .ok_or_else(|| terror::Error::fatal("path limit reached"))?;
                // peer is using a new address: validate it before relying on it
                if self.state == ConnectionState::Connected {
                    self.paths.get_mut(i).unwrap().request_validation();
                }
                i
            }
        };

        // anti-amplification accounting is per datagram, not per coalesced packet
        self.paths
            .get_mut(pid)
            .unwrap()
            .on_datagram_received(buffer.len(), Instant::now());

        let mut header = packet::Header::from_bytes(buffer, endpoint::LOCAL_CID_LEN)?;

        // process the first packet
        let mut offset = self
            .recv_single(buffer, &mut header, pid)
            .inspect_err(|e| {
                // Check if we encountered a quic protocol error
                if (0x01..=0x10).contains(&e.kind()) {
                    self.pec = Some((e.kind(), self.lft));
                    self.state = ConnectionState::Closing;
                }
            })?;
        let mut remaining: usize = buffer.len() - offset;

        debug!("processed packet with {} bytes", offset);

        let mut packet_type = header.hf >> 7;

        // while the last decoded packet is not a short packet, try and decode coalesced packets
        while packet_type != 0 && remaining > 0 {
            let mut partial_decode = packet::Header::from_bytes(&buffer[offset..], 8)?;

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

    // returns processed bytes
    #[tracing::instrument(skip_all, fields(space = header.space()))]
    fn recv_single(
        &mut self,
        packet: &mut [u8],
        header: &mut Header,
        path: usize,
    ) -> Result<usize, terror::Error> {
        let now = Instant::now();
        debug!("header: {}", header);

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

        // retry, client only
        if ((header.hf & packet::LS_TYPE_BIT) >> 7) == 0x01
            && ((header.hf & packet::LONG_PACKET_TYPE) >> 4) == 0x03
        {
            todo!("retry packets not yet implemented");
            // TODO return self.process_retry(buffer, &header);
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

        // track received bytes as one cidm refresh trigger
        self.cidm.on_bytes_received(payload.len() as u64);

        // TODO path handling here after decryption

        self.process_payload(header, &mut payload, path, now)?;

        // test if all required crypto data has been exchanged for the connection to be
        // considered established
        if self.state < ConnectionState::Connected
            && !self.tls_session.is_handshaking()
            && self.tls_session.alpn_protocol().is_some()
            && self.tls_session.negotiated_cipher_suite().is_some()
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

            if self.side == Side::Server {
                self.handshake_done_pending = true;
            }
        }

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
        debug!("header: {}", header);

        // skip forth to packet payload
        payload.skip(header.raw_length + header.packet_num_length as usize + 1)?;

        self.process_payload(header, &mut payload, path, now)?;

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
                    let offset = payload.get_varint()?;
                    let data = payload.get_bytes_with_varint_length()?;

                    let tls = &mut self.tls_session;
                    self.packet_spaces[header.space()].crypto_rx.recv(
                        offset,
                        data.buf(),
                        |contiguous| {
                            tls.read_hs(contiguous)
                                .map_err(|e| terror::Error::crypto_error(format!("read_hs: {e}")))
                        },
                    )?;

                    self.on_crypto_data()?;
                    self.generate_crypto_data();

                    tracing::trace!(
                        "tls_session.alpn_protocol().is_some(): {} !self.tls_session.is_handshaking(): {} self.state: {}",
                        self.tls_session.alpn_protocol().is_some(),
                        !self.tls_session.is_handshaking(),
                        self.state,
                    );
                } //CRYPTO
                0x07 => {
                    if self.side == Side::Client {
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

                    if l < 1 || l as usize > cid::MAX_CID_SIZE {
                        return Err(terror::Error::quic_transport_error(
                            "connection id length outside 1..=20",
                            terror::QuicTransportError::FrameEncodingError,
                        ));
                    }

                    let n_cid = cid::Id::from_slice(payload.get_bytes(l as usize)?.buf());
                    let srt = StatelessResetToken::from(payload.get_bytes(0x10)?.to_vec());

                    debug!(
                        "received new cid from peer: {} (sqn: {}, rpt: {})",
                        n_cid, sqn, rpt
                    );

                    self.cidm.handle_new_cid(sqn, rpt, n_cid, srt)?;
                } //NEW_CONNECTION_ID
                0x19 => {
                    let sqn = payload.get_varint()?;
                    if let Some(retired) = self.cidm.handle_retire_cid(sqn)? {
                        self.events.push(InnerEvent::RetireConnectionId(retired));
                    }
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

                    self.state = ConnectionState::Draining;
                    self.close_deadline = Some(self.paths.active().close_timeout(now));
                    self.events.push(InnerEvent::ClosedByPeer);

                    tracing::warn!(
                        error_code = ec,
                        error_frame = efc,
                        "connection closed by peer: {rp}"
                    );
                } // CONNECTION_CLOSE_FRAME
                0x1e => {
                    if self.side == Side::Server {
                        return Err(terror::Error::quic_transport_error(
                            "received HANDSHAKE_DONE frame as server",
                            terror::QuicTransportError::ProtocolViolation,
                        ));
                    }
                    self.state = ConnectionState::Connected;
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
                .largest()
                .unwrap_or(0)
                < header.packet_num
        {
            debug!(
                "peer migrated to {}, switching active path",
                self.paths.get(path).unwrap().peer_addr
            );
            self.paths.migrate_to(path);
            if !self.paths.get(path).unwrap().is_validated() {
                self.paths.get_mut(path).unwrap().request_validation();
            }

            // also issue an immediate cid change
            self.cidm.trigger_immediate();
        }

        self.packet_spaces[header.space()]
            .received_pns
            .push(header.packet_num);

        if ack_eliciting {
            self.packet_spaces[header.space()].ack_eliciting_received = true;
        }

        // upgrade to handshaking
        if header.space() == SPACE_ID_HANDSHAKE && self.state == ConnectionState::Initial {
            self.state = ConnectionState::Handshake;
        }

        // if we get to here, no error occured and if a protocol error occurs, no frame is the
        // culprit
        self.lft = 0x00;

        Ok(())
    }

    fn process_ack(
        &mut self,
        ack: &AckFrame,
        space: usize,
        path: usize,
        now: Instant,
    ) -> Result<(), terror::Error> {
        let (acked_pns, lost_pns) = match self.paths.get_mut(path) {
            Some(p) => p.on_ack_received(space, ack, now),
            None => return Ok(()),
        };

        debug!(count = acked_pns.len(), space, "processing ACK frame");

        for sp in acked_pns {
            for f in sp.into_frames() {
                match f {
                    cc::SentFrame::Stream { id, off, len, .. } => {
                        if let Some(ev) = self.sm.ack(id, off, len) {
                            self.events.push(ev);
                        }
                    }
                    cc::SentFrame::Crypto { off, len } => {
                        self.packet_spaces[space].crypto_tx.ack(off, len as usize);
                    }
                    cc::SentFrame::Ack { largest } => {
                        // our ack was acked. discard pn tracking for everything below largest acked
                        self.packet_spaces[space]
                            .received_pns
                            .remove_below(largest + 1);
                    }
                    cc::SentFrame::NewCid { .. } => {
                        self.cidm.ack_new_connection_id_frame();
                    }
                    cc::SentFrame::RetireCid { .. } => {
                        self.cidm.ack_retire_connection_id_frame();
                    }
                    _ => (),
                }
            }
        }

        if !lost_pns.is_empty() {
            warn!(
                count = lost_pns.len(),
                space, "packets declared lost after ACK"
            );
        }

        for sp in lost_pns {
            for f in sp.into_frames() {
                match f {
                    cc::SentFrame::Stream { id, off, len, .. } => {
                        self.sm.lost(id, off, len);
                    }
                    cc::SentFrame::Crypto { off, len } => {
                        self.packet_spaces[space].crypto_tx.lost(off, len as usize);
                    }
                    cc::SentFrame::NewCid { seq } => self.cidm.on_new_cid_lost(seq),
                    cc::SentFrame::RetireCid { seq } => self.cidm.on_retire_cid_lost(seq),
                    cc::SentFrame::HandshakeDone => self.handshake_done_pending = true,
                    _ => {}
                }
            }
        }

        Ok(())
    }

    fn on_crypto_data(&mut self) -> Result<(), terror::Error> {
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
                let tpc = TransportConfig::decode(raw)?;
                self.remote_tpc = Some(tpc);
                let rtpc = self.remote_tpc.as_ref().unwrap();

                let tp_err = |m: &'static str| {
                    terror::Error::quic_transport_error(
                        m,
                        terror::QuicTransportError::TransportParameterError,
                    )
                };
                let is_server = self.side == Side::Server;

                // initial scid: both sides, must be present and equal the peer's actual initial scid
                match rtpc.initial_source_connection_id.as_ref() {
                    Some(iscid) if iscid.get() == self.cidm.get_dcid() => {}
                    Some(_) => return Err(tp_err("initial_source_connection_id mismatch")),
                    None => return Err(tp_err("missing initial_source_connection_id")),
                }

                // original dcid: client-only, server must reject if a client sent one
                match (&rtpc.original_destination_connection_id, is_server) {
                    (Some(_), true) => {
                        return Err(tp_err("client sent original_destination_connection_id"))
                    }
                    (Some(odcid), false) => {
                        let local_odcid = self.cidm.original_dcid().ok_or_else(|| {
                            terror::Error::fatal("client has no original dcid to validate against")
                        })?;
                        if odcid.get() != local_odcid {
                            return Err(tp_err("original_destination_connection_id mismatch"));
                        }
                    }
                    (None, false) => {
                        return Err(tp_err("missing original_destination_connection_id"))
                    }
                    (None, true) => {}
                }

                // stateless_reset_token: server-only, client stores it, server rejects
                if let Some(_srt) = rtpc.stateless_reset_token.as_ref() {
                    if is_server {
                        return Err(tp_err("client sent stateless_reset_token"));
                    }
                    // TODO(client) register `_srt` as the reset token for the server's active handshake cid
                }

                // stream / flow-control limits
                let (imd, imsdbl, imsdbr, imsdu, imsb, imsu) = rtpc.get_initial_limits();
                self.sm.set_initial_data_limits(imsdbl, imsdbr, imsdu);
                self.sm.set_max_data(imd);
                self.sm.set_max_streams_bidi(imsb);
                self.sm.set_max_streams_uni(imsu);

                // active_connection_id_limit
                let acidl = rtpc.active_connection_id_limit.get().get();
                if acidl < 2 {
                    return Err(tp_err("active_connection_id_limit below 2"));
                }
                self.cidm.set_peer_cid_limit(acidl);

                // congestion control
                self.paths
                    .active_mut()
                    .cc_mut()
                    .set_ack_delay_exponent(rtpc.ack_delay_exponent);
                self.paths.active_mut().cc_mut().set_max_ack_delay(
                    std::time::Duration::from_millis(rtpc.max_ack_delay.get().get()),
                );

                // TODO max_udp_payload_size
                // TODO max_idle_timeout
                // TODO disable_active_migration
                // TODO preferred_address
            }
        }

        Ok(())
    }

    fn generate_crypto_data(&mut self) {
        loop {
            let mut buf: Vec<u8> = Vec::new();
            let kc = self.tls_session.write_hs(&mut buf);

            if !buf.is_empty() {
                debug!(
                    "generated {} crypto bytes in space {}",
                    buf.len(),
                    self.current_space
                );
                self.packet_spaces[self.current_space]
                    .crypto_tx
                    .append(&buf);
            }

            let done = buf.is_empty() && kc.is_none();

            match kc {
                Some(KeyChange::Handshake { keys }) => {
                    self.packet_spaces[SPACE_ID_HANDSHAKE].keys = Some(keys);
                    self.packet_spaces[SPACE_ID_HANDSHAKE].active = true;
                    self.current_space = SPACE_ID_HANDSHAKE;
                    debug!("handshake keyset ready");
                }
                Some(KeyChange::OneRtt { keys, mut next }) => {
                    self.packet_spaces[SPACE_ID_DATA].keys = Some(keys);
                    self.packet_spaces[SPACE_ID_DATA].active = true;
                    self.next_1rtt_packet_keys = Some(next.next_packet_keys());
                    self.next_secrets = Some(next);
                    self.current_space = SPACE_ID_DATA;
                    debug!("data (1-rtt) keyset ready");
                }
                None => {}
            }

            if done {
                break;
            }
        }
    }

    // TODO return if there is more to send
    fn fetch_dgram(&mut self, buffer: &mut [u8]) -> Result<usize, terror::Error> {
        if self.state == ConnectionState::Closed || self.state == ConnectionState::Draining {
            tracing::error!("cannot fetch packet from closed connection");
            return Ok(0);
        }

        let cwnd = self.paths.active().cwnd_available();
        let budget = self.paths.active().send_budget();
        let max_payload_size = self
            .remote_tpc
            .as_ref()
            .map(|t| t.max_udp_payload_size.get().get() as usize)
            .unwrap_or(1200);
        let mut remaining = buffer.len().min(cwnd).min(budget).min(max_payload_size);

        tracing::debug!("remaining buffer size: {remaining}");

        let mut written: usize = 0;

        let mut contains_initial = false;
        let mut encoded_packets: usize = 0;

        //let mut ack_eliciting = false;

        while remaining > 0 {
            tracing::trace!(connection_state = %self.state, close_sent = self.close_sent, "current state");
            if self.state == ConnectionState::Closing && self.close_sent {
                break;
            }

            let (packet_type, space_id) = self.get_packet_type();
            let mut frames: SmallVec<[cc::SentFrame; 2]> = SmallVec::new();
            let mut ack_eliciting = false;

            let span = span!(
                Level::DEBUG,
                "fetch_dgram",
                space = space_id,
                packet_t = %packet_type,
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

            let now = Instant::now();
            let pn = self.packet_spaces[space_id].get_next_pkt_num();
            let dcid = self.cidm.get_dcid();

            span.record("pn", pn);

            //debug!("header: {}", header);

            let keys = if let Some(crypto) = self.packet_spaces[space_id].keys.as_ref() {
                &crypto.local
            } else {
                return Err(terror::Error::crypto_error(format!(
                    "no availible keys in space {}",
                    space_id
                )));
            };

            let aead_tag_len = keys.packet.tag_len();

            let (packet_size_overhead, want_initial) = match packet_type {
                packet::PacketType::Short => (
                    packet::Header::short_header_len(dcid, pn) + aead_tag_len,
                    false,
                ),
                _ => {
                    let initial = packet_type == packet::PacketType::Initial;
                    let lht = if initial {
                        packet::LONG_HEADER_TYPE_INITIAL
                    } else {
                        packet::LONG_HEADER_TYPE_HANDSHAKE
                    };
                    let token = None; // TODO for retry packets
                    (
                        packet::Header::long_header_len(lht, dcid, self.cidm.get_scid(), token, pn)
                            + aead_tag_len,
                        initial,
                    )
                }
            };

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

            let mut buf = octets::OctetsMut::with_slice(&mut buffer[written..written + remaining]);

            // encode header and keep track of where the length field has been encoded
            if want_initial {
                contains_initial = true;
            }

            let (pn_length, length_field_offset) = match packet_type {
                packet::PacketType::Short => {
                    packet::Header::encode_short(&mut buf, 0, 0, dcid, pn)?
                }
                _ => {
                    let lht = if want_initial {
                        packet::LONG_HEADER_TYPE_INITIAL
                    } else {
                        packet::LONG_HEADER_TYPE_HANDSHAKE
                    };
                    let token = None; // TODO for retry packets

                    packet::Header::encode_long(
                        &mut buf,
                        lht,
                        self.version,
                        dcid,
                        self.cidm.get_scid(),
                        token,
                        pn,
                    )?
                }
            };

            let mut path_challenge_sent: Option<[u8; 8]> = None;

            let payload_offset = buf.off();

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
                        self.close_sent = true;
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

                debug!(
                    count = self.packet_spaces[space_id].received_pns.len(),
                    ack_delay, "encoding ACK frame"
                );

                // directly generate ack frame from packet number vector

                // TODO there is a bug here. If frame was too small, directly passing the octets buf
                // still advances it, effectively writing a corrupted frame

                match AckFrame::to_bytes(
                    // TODO decide if we want to do something with the error
                    &self.packet_spaces[space_id].received_pns,
                    None, // TODO figure out
                    ack_delay,
                    &mut buf,
                ) {
                    Ok(size) => {
                        tracing::trace!(
                            "encoded ACK frame: {:?}",
                            &buf.buf()[buf.off() - size..buf.off()]
                        );

                        //clear vector as packet numbers are now ack'ed
                        self.packet_spaces[space_id].latest_ack_recv_time = None;
                        self.packet_spaces[space_id].ack_eliciting_received = false;

                        // add to cc tracking
                        frames.push(cc::SentFrame::Ack {
                            largest: self.packet_spaces[space_id]
                                .received_pns
                                .largest()
                                .unwrap_or(0),
                        });
                    }
                    Err(err) => tracing::error!("failed to encode ACK frame: {err}"),
                };
            };

            // clear queued crypto frames in case the connection is beeing closed
            if is_closing {
                self.packet_spaces[space_id].crypto_tx.clear();
            } else {
                // if not, encode them
                loop {
                    match self.packet_spaces[space_id].crypto_tx.emit(&mut buf) {
                        Ok(Some((off, len))) => {
                            frames.push(cc::SentFrame::Crypto {
                                off,
                                len: len as u32,
                            });
                            ack_eliciting = true;
                        }
                        Ok(None) => break,
                        Err(e) => {
                            warn!("crypto emit failed: {e}");
                            break;
                        }
                    }
                }
            }

            // stream & cid frames
            if packet_type == packet::PacketType::Short && !is_closing {
                // HANDSHAKE_DONE, server only (can only be flipped to true on server side)
                if self.handshake_done_pending && buf.cap() >= 1 {
                    buf.put_u8(0x1e)?;
                    self.handshake_done_pending = false;
                    ack_eliciting = true;
                    frames.push(cc::SentFrame::HandshakeDone);
                }

                // PATH_RESPONSE, echo any received challenges first
                while buf.cap() >= 9 {
                    match self.paths.active_mut().poll_response() {
                        Some(data) => {
                            let start = buf.off();
                            buf.put_u8(0x1b)?;
                            buf.put_u64(u64::from_be_bytes(data))?;
                            tracing::trace!(
                                "encoded PATH_RESPONSE frame: {:?}",
                                &buf.buf()[start..buf.off()]
                            );
                            ack_eliciting = true;
                        }
                        None => break,
                    }
                }

                // PATH_CHALLENGE, emit one if the active path wants validating
                if self.paths.active().probing_required() && buf.cap() >= 9 {
                    let mut b = [0u8; 8];
                    rand::rng().fill_bytes(&mut b);
                    let start = buf.off();
                    buf.put_u8(0x1a)?;
                    buf.put_u64(u64::from_be_bytes(b))?;
                    tracing::trace!(
                        "encoded PATH_CHALLENGE frame: {:?}",
                        &buf.buf()[start..buf.off()]
                    );
                    ack_eliciting = true;
                    path_challenge_sent = Some(b);
                }

                // NEW_CONNECTION_ID frame
                let new_cid_len = self.cidm.next_new_cid_len(now);
                if new_cid_len > 0 && buf.cap() >= new_cid_len {
                    if let Some((sqn, rpt, id, srt)) =
                        self.cidm.issue_new_cid(&self.hmac_reset_token_key, now)
                    {
                        let start = buf.off();
                        buf.put_u8(0x18)?;
                        buf.put_varint(sqn)?;
                        buf.put_varint(rpt)?;
                        buf.put_u8(id.len() as u8)?;
                        buf.put_bytes(id.as_slice())?;
                        buf.put_bytes(&srt.token)?;
                        debug_assert_eq!(buf.off() - start, new_cid_len);
                        tracing::trace!(%id, sqn, rpt, "encoded NEW_CONNECTION_ID frame: {:?}", &buf.buf()[start..buf.off()]);
                        self.events.push(InnerEvent::NewConnectionId(id));
                        frames.push(cc::SentFrame::NewCid { seq: sqn });
                        self.cidm.add_new_connection_id_frame();
                        ack_eliciting = true;
                    }
                }

                // RETIRE_CONNECTION_ID frame
                let retire_len = self.cidm.next_retire_cid_len();
                if retire_len > 0 && buf.cap() >= retire_len {
                    let start = buf.off();
                    let sqn = self.cidm.pop_retire_cid();
                    buf.put_u8(0x19)?;
                    buf.put_varint(sqn)?;
                    debug_assert_eq!(buf.off() - start, retire_len);
                    tracing::trace!(
                        sqn,
                        "encoded RETIRE_CONNECTION_ID frame: {:?}",
                        &buf.buf()[start..buf.off()]
                    );
                    frames.push(cc::SentFrame::RetireCid { seq: sqn });
                    self.cidm.add_retire_connection_id_frame();
                    ack_eliciting = true;
                }

                // create STREAMS_BLOCKED if bidi streams are blocked
                if let Some(seq) = self.sm.bidi_streams_blocked() {
                    let start = buf.off();
                    buf.put_varint(0x16)?;
                    buf.put_varint(seq)?;
                    tracing::trace!(
                        seq,
                        "encoded STREAMS_BLOCKED (bidi) frame: {:?}",
                        &buf.buf()[start..buf.off()]
                    );
                    ack_eliciting = true;
                }

                // create STREAMS_BLOCKED if uni streams are blocked
                if let Some(seq) = self.sm.uni_streams_blocked() {
                    let start = buf.off();
                    buf.put_varint(0x17)?;
                    buf.put_varint(seq)?;
                    tracing::trace!(
                        seq,
                        "encoded STREAMS_BLOCKED (uni) frame: {:?}",
                        &buf.buf()[start..buf.off()]
                    );
                    ack_eliciting = true;
                }

                // create MAX_STREAM_DATA frames for connection
                self.sm.upgrade_max_stream_data(&mut buf)?;

                // create MAX_STREAMS to increase our recv stream limit
                self.sm.upgrade_peer_stream_limits(&mut buf)?;

                // create MAX_DATA for connection, buffer req: frame code (1) + max max_data (8)
                if self.sm.nearly_full()
                    && buf.cap() > varint_len(self.sm.max_data() + fc::MAX_WINDOW_CONNECTION)
                {
                    let n_md = self.sm.upgrade_max_data();
                    let start = buf.off();

                    buf.put_varint(0x10)?;
                    buf.put_varint(n_md)?;
                    tracing::trace!(
                        new_max_data = n_md,
                        "encoded MAX_DATA frame: {:?}",
                        &buf.buf()[start..buf.off()]
                    );
                    ack_eliciting = true;
                }

                // encode stream frame last to ensure enough room for flow control frames.
                // implicitly encodes DATA_BLOCKED, STREAM_DATA_BLOCKED
                let start = buf.off();
                let bytes = self.sm.emit_fill(buf.as_mut(), &mut frames)?;
                buf.skip(bytes)?;

                if bytes > 0 {
                    tracing::trace!("encoded STREAM frame: {:?}", &buf.buf()[start..buf.off()]);
                }

                if bytes > 0 {
                    ack_eliciting = true;
                }

                // PTO probe: if a probe is required but no ack-eliciting frame has been
                // written yet, emit a PING. This satisfies the probe obligation without
                // any retransmission logic; probe_pending is cleared by on_packet_sent
                // TODO include in if how many ack only packets have been sent to prevent a one
                // sided stream to fill our pn tracking
                if self.paths.active().cc().probe_pending() && !ack_eliciting && buf.cap() >= 1 {
                    buf.put_u8(0x01)?;
                    ack_eliciting = true;
                    frames.push(cc::SentFrame::Ping);
                }
            }

            // if is last packet, pad to min size of 1200
            if contains_initial
                && !self.packet_spaces[std::cmp::min(space_id + 1, SPACE_ID_DATA)].wants_write()
            {
                // if packet header is long, add padding length to length field, if it is short skip
                // padding length
                let target = 1200usize.saturating_sub(written + aead_tag_len);
                if buf.off() < target {
                    let skip = (target - buf.off()).min(buf.cap());
                    tracing::trace!(
                        "datagram contains initial frame and this last packet is padded by: {}",
                        skip
                    );
                    buf.as_mut()[..skip].fill(0);
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
                tracing::trace!("padding packet by {target} because it contains a path challenge");
            }

            let payload_length = buf.off() - payload_offset;
            debug!("packet payload length: {}", payload_length);

            // determine length of packet and encode it
            if let Some(lfo) = length_field_offset {
                let length = payload_length + aead_tag_len + (pn_length as usize + 1);
                packet::Header::patch_length(&mut buf, lfo, length)?;
            }

            // encrypt the packet
            let packet_length = packet::encrypt(&mut buf, keys, pn, payload_offset)?;

            debug!("packet_length: {}", packet_length);

            self.paths.active_mut().on_packet_sent(
                pn,
                space_id,
                packet_length,
                ack_eliciting,
                now,
                frames,
            );

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
        for space in SPACE_ID_INITIAL..=SPACE_ID_HANDSHAKE {
            if self.packet_spaces[space].wants_write() {
                return (packet::PacketType::from(space), space);
            }
        }

        let data = &self.packet_spaces[SPACE_ID_DATA];
        if data.active && (data.wants_write() || self.data_space_has_frames()) {
            return (packet::PacketType::from(SPACE_ID_DATA), SPACE_ID_DATA);
        }

        (packet::PacketType::None, 0)
    }

    fn data_space_has_frames(&self) -> bool {
        self.sm.has_pending()
            || self.sm.nearly_full()
            || self.cidm.wants_write()
            || self.paths.active().probing_required()
            || self.paths.active().has_pending_response()
            || self.handshake_done_pending
            || self.paths.active().cc().probe_pending()
    }

    pub fn poll_events(&mut self) -> Vec<InnerEvent> {
        std::mem::take(&mut self.events)
    }
}

/// emitted after a packet is received. can be polled via [`Inner::poll_event(&mut self)`].
enum InnerEvent {
    /// emitted once per connection when it is established and becomes available to the application
    ConnectionEstablished,

    /// emitted only when we (our side) issue a new connection id to out peer so that the io
    /// layer knows which connection ids to match to which connection
    NewConnectionId(cid::Id),

    /// emitted we receive an RETIRE_CONNECTION_ID from our peer, indicating it wont use that id
    /// anymore to address our endpoint
    RetireConnectionId(cid::Id),

    /// emitted when the connection has been closed by the peer
    ClosedByPeer,

    /// emitted by the stream manager if a new stream can be opened if a previous try was made to
    /// open a new stream but was blocked by flow control limits of the peer. the bool indicates
    /// if its a bidi stream (true) or a uni stream (false)
    StreamOpenable(bool),

    /// emitted by the stream manager if a new stream can be accepted if a previous try was made to
    /// accept a new stream but no new stream was available. the bool indicates if its a bidi
    /// stream (true) or a uni stream (false)
    StreamAcceptable(bool),

    /// emitted by the stream manager if a stream has new data than can be read if a previous read
    /// call was issued but no data was available. contains stream id
    StreamReadable(u64),

    /// emitted by stream manager if a send stream can now send data again after a previous write
    /// call was issued but local buffer limits blocked writing additional data. contains stream id
    StreamWritable(u64),

    /// emitted by stream manager if a stream is finished, meaning the fin bit has been set and all
    /// data has been sent and ack'ed
    StreamFinished(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
enum ConnectionState {
    Initial,
    Handshake,
    Connected,
    Closing,
    Draining,
    Closed,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Initial => write!(f, "Initial"),
            ConnectionState::Handshake => write!(f, "Handshake"),
            ConnectionState::Connected => write!(f, "Connected"),
            ConnectionState::Closing => write!(f, "Closing"),
            ConnectionState::Draining => write!(f, "Draining"),
            ConnectionState::Closed => write!(f, "Closed"),
        }
    }
}

/// RFC 9000 section 12.3. we have 3 packet number spaces: initial, handshake & 1-RTT
struct PacketNumberSpace {
    /// current active keyset
    keys: Option<Keys>,

    /// received pns sorted in range set
    received_pns: RangeSet,

    // timestamp of the most recent ack-eliciting packet received in this space.
    // used to compute the ack delay field
    latest_ack_recv_time: Option<Instant>,
    ack_eliciting_received: bool,

    /// crypto send stream
    crypto_tx: stream::CryptoSend,

    /// crypto recv stream
    crypto_rx: stream::CryptoRecv,

    /// next packet number for outgoing packet
    next_pkt_num: u64,

    /// if this packet number space is active
    active: bool,
}

impl PacketNumberSpace {
    fn new() -> Self {
        Self {
            keys: None,
            received_pns: RangeSet::new(64),
            latest_ack_recv_time: None,
            ack_eliciting_received: false,
            crypto_tx: stream::CryptoSend::default(),
            crypto_rx: stream::CryptoRecv::default(),
            next_pkt_num: 0,
            active: false,
        }
    }

    //determines if a space has outgoing crypto data or acks
    fn wants_write(&self) -> bool {
        self.active && (self.ack_eliciting_received || self.crypto_tx.wants_write())
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
