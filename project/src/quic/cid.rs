use crate::{terror, token::StatelessResetToken};
use smallvec::SmallVec;

use rand::RngCore;
use std::fmt;
use tracing::warn;

pub const MAX_CID_SIZE: usize = 0x14;

const MAX_CID_RETIREMENTS_IN_FLIGHT: usize = 0x04;
const MAX_NEW_CIDS_IN_FLIGHT: usize = 0x04;

#[derive(Eq, Hash, PartialEq, Clone, PartialOrd, Ord)]
pub struct Id {
    id: Vec<u8>,
}

impl Id {
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
        Id::from_vec(b[..length].into())
    }
}

impl fmt::Display for Id {
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

impl fmt::Debug for Id {
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

impl Default for Id {
    #[inline]
    fn default() -> Self {
        Self::from_vec(Vec::new())
    }
}

impl From<Vec<u8>> for Id {
    #[inline]
    fn from(v: Vec<u8>) -> Self {
        Self::from_vec(v)
    }
}

#[derive(Debug, Clone)]
struct ConnectionIdEntry {
    id: Id,
    stateless_reset_token: Option<[u8; 16]>,
}

pub struct ConnectionIdManager {
    // dcids (received from peer) & scids (our own)
    // index is sequence number, active cids start at retire_prior_to
    dcids: Vec<Id>,
    scids: Vec<Id>,

    // active connection id limit (from our peer), i.e. how many they are willing to maintain, we
    // must not issue more active ids than this limit
    peer_cid_limit: u64,

    // active cid limit we sent to our peer, used only to enforce limit
    local_cid_limit: u64,

    // retire prior to tracking
    dcid_rpt_sqn: u64,
    scid_rpt_sqn: u64,

    // initial connection ids (immutable after handshake)
    retry_scid: Option<Id>,
    original_dcid: Option<Id>,
    initial_scid: Option<Id>,

    // rotation-based tracking of time and received bytes plus an immediate trigger, for example
    // used on path change / NAT rebinding / migration to trigger issuance of new cid
    last_issued: std::time::Instant,
    recv_byte_counter: u64,
    immediate: bool,

    // retired connection ids awaiting RETIRE_CONNECTION_ID frame transmission
    pending_cid_retirements: Vec<u64>,

    // in-flight retirements. we limit ourselves to a maximum of one retired cid per packet.
    // vec contains tuple of packet number and the retired cids sqn.
    cid_retirements_if: SmallVec<[(u64, u64); MAX_CID_RETIREMENTS_IN_FLIGHT]>,

    // in-flight NEW_CONNECTION_ID frames. we limit ourselves to a max of one new cid per packet.
    // vec contains tuple of (pn, sqn, rpt) so we can trivially reconstruct it in case of loss.
    new_cid_if: SmallVec<[(u64, u64, u64); MAX_NEW_CIDS_IN_FLIGHT]>,

    // track RETIRE_CONNECTION_ID frames that we expect to receive after we issued a
    // NEW_CONNECTION_ID frame with an increased rpt field. vec of sqns of cids
    awaiting_retire_cid_frames: Vec<u64>,
}

impl ConnectionIdManager {
    fn new(
        dcids: Vec<Id>,
        scids: Vec<Id>,
        retry_scid: Option<Id>,
        original_dcid: Option<Id>,
        initial_scid: Option<Id>,
        local_cid_limit: u64,
    ) -> Self {
        Self {
            dcids,
            scids,
            peer_cid_limit: 0,
            local_cid_limit,
            dcid_rpt_sqn: 0,
            scid_rpt_sqn: 0,
            retry_scid,
            original_dcid,
            initial_scid,
            last_issued: std::time::Instant::now(),
            recv_byte_counter: 0,
            immediate: false,
            pending_cid_retirements: Vec::new(),
            cid_retirements_if: SmallVec::new(),
            new_cid_if: SmallVec::new(),
            awaiting_retire_cid_frames: Vec::new(),
        }
    }

    // the connection id that a client selects for the first dcid field it sends and any connection id
    // provided by a retry packet are not assigned sequence numbers.
    // the first dcid is entered into the dcid vector, despite it having no formal sqn. as soon as
    // the servers initial packet with its choice arrives, it is replaced
    pub fn as_client(initial_dcid: Id, initial_scid: Id, local_cid_limit: u64) -> Self {
        Self::new(
            vec![initial_dcid.clone()],
            vec![initial_scid.clone()],
            None,
            Some(initial_dcid),
            Some(initial_scid),
            local_cid_limit,
        )
    }

    pub fn as_server(
        initial_dcid: Id,
        initial_scid: Id,
        original_dcid: Id,
        local_cid_limit: u64,
    ) -> Self {
        Self::new(
            vec![initial_dcid],
            vec![initial_scid.clone()],
            None,
            Some(original_dcid),
            Some(initial_scid),
            local_cid_limit,
        )
    }

    // client only, used to replace dcid (sqn=0) for server after its initial packet arrives
    pub fn replace_initial_dcid(&mut self, connection_id: Id) {
        assert_eq!(*self.original_dcid.as_ref().unwrap(), self.dcids[0]);
        self.dcids[0] = connection_id;
    }

    // returns a valid scid
    pub fn get_scid(&self) -> &Id {
        &self.scids[self.scid_rpt_sqn as usize]
    }

    // returns a valid dcid
    pub fn get_dcid(&self) -> &Id {
        &self.dcids[self.dcid_rpt_sqn as usize]
    }

    pub fn handle_new_cid(
        &mut self,
        sqn: u64,
        rpt: u64,
        cid: Id,
        _srt: StatelessResetToken,
    ) -> Result<(), terror::Error> {
        if rpt > sqn {
            return Err(terror::Error::quic_transport_error(
                "retire_prior_to is greater than the sequence number",
                terror::QuicTransportError::FrameEncodingError,
            ));
        }

        // if the sequence number is lower than retire prior to, the new cid is either a
        // retransmission and already retired or must be immediately retired
        if sqn < self.dcid_rpt_sqn {
            if !self.pending_cid_retirements.contains(&sqn) {
                self.pending_cid_retirements.push(sqn);
            }
            return Ok(());
        }

        // check if new retire_prior_to is higher than current
        if rpt > self.dcid_rpt_sqn {
            self.pending_cid_retirements
                .append(&mut (self.dcid_rpt_sqn..rpt).collect());
            self.dcid_rpt_sqn = rpt;
        }

        if self.dcids.len() < sqn as usize {
            return Err(terror::Error::quic_transport_error(
                "sequence number is increasing by more than one",
                terror::QuicTransportError::ProtocolViolation,
            ));
        }

        // if exactly next cid, save cid, assume if sqn lower, its a retransmission and both cids
        // match
        if self.dcids.len() == sqn as usize {
            self.dcids.push(cid);
        }

        // check active_connection_id_limit
        if (self.dcids.len() as u64 - self.dcid_rpt_sqn) > self.local_cid_limit {
            return Err(terror::Error::quic_transport_error(
                "peer exceeded local connection id limit",
                terror::QuicTransportError::ConnectionIdLimitError,
            ));
        }

        Ok(())
    }

    pub fn handle_retire_cid(&mut self, sqn: u64) -> Result<(), terror::Error> {
        // we havent even issued that cid or its our last
        if sqn as usize >= self.scids.len() - 1 {
            return Err(terror::Error::quic_transport_error(
                "received retire cid frame with sequence number referring to highest or non-issued cid",
                terror::QuicTransportError::ProtocolViolation,
            ));
        }

        self.scid_rpt_sqn = std::cmp::max(self.scid_rpt_sqn, sqn + 1);

        Ok(())
    }

    /// returns true if one of three triggers turn true. first is that the number of active cids is
    /// lower than the peers limit. second is a time based trigger. third is a data based trigger.
    /// immediate is triggered on path change / nat rebinding / migration.
    pub fn should_issue_cid(&self) -> bool {
        //TODO make thresholds configurable
        let under_limit = ((self.scids.len() as u64) - self.scid_rpt_sqn) < self.peer_cid_limit;
        let time_elapsed =
            std::time::Instant::now() - self.last_issued >= std::time::Duration::new(5 * 60, 0);
        let bytes_threshold = self.recv_byte_counter >= (1024 * 1024 * 16);

        under_limit | time_elapsed | bytes_threshold | self.immediate
    }

    /// issues a new cid for our peer, aka our scid, their dcid. returns (sqn, rpt, id, srt). may
    /// return none if issuing a new cid would be invalid
    pub fn issue_new_cid(
        &mut self,
        hmac_key: &ring::hmac::Key,
        packet_number: u64,
    ) -> Option<(u64, u64, Id, StatelessResetToken)> {
        if !self.should_issue_cid() {
            return None;
        }

        if self.new_cid_if.len() >= MAX_NEW_CIDS_IN_FLIGHT {
            warn!("issuing a new cid would exceed the in-flight limit");
            return None;
        }

        // generate new cid
        let id = Id::generate_with_length(8);
        let sqn = self.scids.len() as u64;

        // save id
        self.scids.push(id.clone());

        // figure out if we need to increase retire prior to
        let under_limit = ((self.scids.len() as u64) - self.scid_rpt_sqn) <= self.peer_cid_limit;
        if !under_limit {
            self.awaiting_retire_cid_frames.push(self.scid_rpt_sqn);
            self.scid_rpt_sqn += 1;
        }

        // generate stateless reset token, TODO use module as soon as new Cid is in Programm
        let signature = ring::hmac::sign(hmac_key, id.as_slice()).as_ref().to_vec();
        let mut result = [0u8; 0x10];
        result.copy_from_slice(&signature[..0x10]);
        let result_vec = result.to_vec();
        let srt = StatelessResetToken::from(result_vec);

        // save issued time for time-based trigger
        self.last_issued = std::time::Instant::now();

        // save into in-flight vec
        self.new_cid_if
            .push((packet_number, sqn, self.scid_rpt_sqn));

        Some((sqn, self.scid_rpt_sqn, id, srt))
    }

    /// removes incoming acked frames from in-flight tracking structures
    pub fn ack_in_flight(&mut self, pns: Vec<u64>) {
        self.cid_retirements_if
            .retain(|(pn, _sqn)| !pns.contains(pn));
        self.new_cid_if.retain(|(pn, _sqn, _rpt)| !pns.contains(pn));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static HMAC_KEY: std::sync::OnceLock<ring::hmac::Key> = std::sync::OnceLock::new();
    static HMAC_RESET_KEY_VALUE: std::sync::OnceLock<[u8; 64]> = std::sync::OnceLock::new();

    fn get_cid_manager(num_dcids: u64, num_scids: u64) -> ConnectionIdManager {
        let mut dcids: Vec<Id> = vec![];
        let mut scids: Vec<Id> = vec![];

        for _ in 0..num_dcids {
            dcids.push(Id::generate_with_length(8));
        }

        for _ in 0..num_scids {
            scids.push(Id::generate_with_length(8));
        }

        ConnectionIdManager {
            dcids,
            scids,
            peer_cid_limit: 4,
            local_cid_limit: 4,
            dcid_rpt_sqn: 0,
            scid_rpt_sqn: 0,
            retry_scid: None,
            original_dcid: None,
            initial_scid: None,
            last_issued: std::time::Instant::now(),
            recv_byte_counter: 0,
            immediate: false,
            pending_cid_retirements: Vec::new(),
            cid_retirements_if: SmallVec::new(),
            new_cid_if: SmallVec::new(),
            awaiting_retire_cid_frames: Vec::new(),
        }
    }

    // helper
    fn init_hmac_key_value() -> &'static [u8; 64] {
        HMAC_RESET_KEY_VALUE.get_or_init(|| {
            let mut arr = [0u8; 64];
            rand::thread_rng().fill_bytes(&mut arr);
            arr
        })
    }

    // helper
    fn init_hmac_reset_key() -> &'static ring::hmac::Key {
        HMAC_KEY
            .get_or_init(|| ring::hmac::Key::new(ring::hmac::HMAC_SHA256, init_hmac_key_value()))
    }

    // helper
    fn get_srt(id: &Id) -> StatelessResetToken {
        let key = init_hmac_reset_key();
        let signature = ring::hmac::sign(key, id.as_slice()).as_ref().to_vec();
        let mut result = [0u8; 0x10];
        result.copy_from_slice(&signature[..0x10]);
        let result_vec = result.to_vec();
        StatelessResetToken::from(result_vec)
    }

    // a helper to make deterministic test keys
    fn test_key() -> ring::hmac::Key {
        let bytes = [0xAB; 32];
        ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &bytes)
    }

    #[test]
    fn connection_establishment_client_to_server() {
        let c_initial_dcid = Id::generate_with_length(8);
        let c_initial_scid = Id::generate_with_length(8);

        // client MAYBE make id generation only possible in manager so ids are directly stored
        let mut c_cid_manager =
            ConnectionIdManager::as_client(c_initial_dcid.clone(), c_initial_scid.clone(), 4);

        // server get initialized with inital packet
        let s_initial_scid = Id::generate_with_length(8);

        let s_cid_manager = ConnectionIdManager::as_server(
            c_initial_scid.clone(),
            s_initial_scid.clone(),
            c_initial_dcid,
            4,
        );

        // server should answer with correct dcid and scid in initial packet
        assert_eq!(c_initial_scid, s_cid_manager.get_dcid().clone());
        assert_eq!(s_initial_scid, s_cid_manager.get_scid().clone());

        // client must then update the servers scid (for client dcid), which is seq = 0
        c_cid_manager.replace_initial_dcid(s_initial_scid.clone());

        // client should then use its own chosen scid and server chose dcid until a
        // NEW_CONNECTION_ID is issued
        assert_eq!(s_initial_scid, c_cid_manager.get_dcid().clone());
        assert_eq!(c_initial_scid, c_cid_manager.get_scid().clone());
    }

    #[test]
    fn valid_new_connection_id() {
        // assume start state after handshake with a single cid for d/s with sqn 0
        let mut idm = get_cid_manager(1, 1);

        let ncid = Id::generate_with_length(8);
        let token = get_srt(&ncid);
        let result = idm.handle_new_cid(1, 0, ncid.clone(), token);

        assert!(result.is_ok());
        assert_eq!(idm.dcids[1], ncid);
    }

    #[test]
    fn invalid_new_cid_limit_exceeded() {
        // assume start state with 4 dcids
        let mut idm = get_cid_manager(4, 1);

        let ncid = Id::generate_with_length(8);
        let token = get_srt(&ncid);
        let result = idm.handle_new_cid(4, 0, ncid.clone(), token);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            terror::QuicTransportError::ConnectionIdLimitError as u64
        );
    }

    #[test]
    fn valid_new_cid_limit_barely_not_exceeded() {
        // assume start state with 4 dcids
        let mut idm = get_cid_manager(4, 1);

        let ncid = Id::generate_with_length(8);
        let token = get_srt(&ncid);
        let result = idm.handle_new_cid(4, 1, ncid.clone(), token);

        assert!(result.is_ok());
        assert_eq!(idm.dcids[4], ncid);
        assert_eq!(idm.dcid_rpt_sqn, 1);
        assert_eq!(idm.pending_cid_retirements[0], 0);
    }

    #[test]
    fn valid_new_cid_retire_all_but_one() {
        // assume start state with 4 dcids
        let mut idm = get_cid_manager(4, 1);

        let ncid = Id::generate_with_length(8);
        let token = get_srt(&ncid);
        let result = idm.handle_new_cid(4, 4, ncid.clone(), token);

        assert!(result.is_ok());
        assert_eq!(idm.dcids[4], ncid);
        assert_eq!(idm.dcid_rpt_sqn, 4);
        assert_eq!(idm.pending_cid_retirements[0], 0);
        assert_eq!(idm.pending_cid_retirements[3], 3);
    }

    #[test]
    fn invalid_new_cid_retire_too_many() {
        // assume start state with 4 dcids
        let mut idm = get_cid_manager(4, 1);

        let ncid = Id::generate_with_length(8);
        let token = get_srt(&ncid);
        let result = idm.handle_new_cid(4, 5, ncid.clone(), token);

        assert!(result.is_err());
        assert_eq!(idm.dcids.len(), 4);
        assert_eq!(idm.dcid_rpt_sqn, 0);
        assert!(idm.pending_cid_retirements.is_empty());
    }

    #[test]
    fn handle_retire_cid_from_peer() {
        // assume start state with 4 dcids
        let mut idm = get_cid_manager(4, 4);

        assert!(!idm.should_issue_cid());

        let mut r = idm.handle_retire_cid(0);

        assert!(r.is_ok());
        assert_eq!(idm.scid_rpt_sqn, 1);
        assert!(idm.should_issue_cid());
        assert_eq!(*idm.get_scid(), idm.scids[1].clone());

        r = idm.handle_retire_cid(1);

        assert!(r.is_ok());
        assert_eq!(idm.scid_rpt_sqn, 2);
        assert!(idm.should_issue_cid());
        assert_eq!(*idm.get_scid(), idm.scids[2].clone());

        r = idm.handle_retire_cid(2);

        assert!(r.is_ok());
        assert_eq!(idm.scid_rpt_sqn, 3);
        assert!(idm.should_issue_cid());
        assert_eq!(*idm.get_scid(), idm.scids[3].clone());

        r = idm.handle_retire_cid(3);

        assert!(r.is_err());
        assert_eq!(idm.scid_rpt_sqn, 3);
        assert!(idm.should_issue_cid());
        assert_eq!(*idm.get_scid(), idm.scids[3].clone());

        r = idm.handle_retire_cid(4);

        assert!(r.is_err());
        assert_eq!(idm.scid_rpt_sqn, 3);
        assert!(idm.should_issue_cid());
        assert_eq!(*idm.get_scid(), idm.scids[3].clone());
    }

    #[test]
    fn issue_new_cid_with_in_flight_limit() {
        // assume state with zero scids
        let mut idm = get_cid_manager(1, 0);
        idm.peer_cid_limit = 5;

        let tk = test_key();

        // first packet
        let mut result = idm.issue_new_cid(&tk, 1);

        assert!(result.is_some());

        let (sqn, rpt, id, _) = result.unwrap(); //TODO verify srt
        assert_eq!(sqn, 0);
        assert_eq!(rpt, 0);
        assert!(idm.scids.ends_with(&[id]));
        assert!(idm.new_cid_if.ends_with(&[(1, 0, 0)]));

        // second packet
        result = idm.issue_new_cid(&tk, 2);

        assert!(result.is_some());

        let (sqn, rpt, id, _) = result.unwrap(); //TODO verify srt
        assert_eq!(sqn, 1);
        assert_eq!(rpt, 0);
        assert!(idm.scids.ends_with(&[id]));
        assert!(idm.new_cid_if.ends_with(&[(2, 1, 0)]));

        // third & fourth packet
        result = idm.issue_new_cid(&tk, 3);
        assert!(result.is_some());
        result = idm.issue_new_cid(&tk, 4);
        assert!(result.is_some());

        // now we got 4 active scids
        assert_eq!(idm.scids.len(), 4);

        // fifth packet, now our in-flight limit is hit
        result = idm.issue_new_cid(&tk, 5);

        assert!(result.is_none());

        // we still want to issue because we got one left in our limit
        assert!(idm.should_issue_cid());

        // assume all in-flight frames got successfully ack'd
        idm.new_cid_if.clear();

        // sixth packet, we can issue again
        result = idm.issue_new_cid(&tk, 6);

        assert!(result.is_some());

        let (sqn, rpt, id, _) = result.unwrap(); //TODO verify srt
        assert_eq!(sqn, 4);
        assert_eq!(rpt, 0);
        assert!(idm.scids.ends_with(&[id]));
        assert!(idm.new_cid_if.ends_with(&[(6, 4, 0)]));

        // now the peers limit is satisfied so we dont want to issue any more
        assert!(!idm.should_issue_cid());
    }

    #[test]
    fn issue_new_cid_through_time_rotation() {
        let mut idm = get_cid_manager(4, 4);
        let tk = test_key();

        // modify last_issued to 5 mins prior now
        idm.last_issued = std::time::Instant::now() - std::time::Duration::new(5 * 60, 0);

        // new cid should be issued due to timed trigger
        let result = idm.issue_new_cid(&tk, 10);

        assert!(result.is_some());

        let (sqn, rpt, id, _) = result.unwrap(); //TODO verify srt
        assert_eq!(sqn, 4);
        assert_eq!(rpt, 1);
        assert!(idm.scids.ends_with(&[id]));
        assert!(idm.new_cid_if.ends_with(&[(10, 4, 1)]));
        assert!(idm.awaiting_retire_cid_frames.ends_with(&[0]));
    }

    #[test]
    fn issue_new_cid_through_recv_bytes_rotation() {
        let mut idm = get_cid_manager(4, 4);
        let tk = test_key();

        // modify so that we received at least 16MB
        idm.recv_byte_counter = (1024 * 1024 * 16) + 1;

        // new cid should be issued due to timed trigger
        let result = idm.issue_new_cid(&tk, 10);

        assert!(result.is_some());

        let (sqn, rpt, id, _) = result.unwrap(); //TODO verify srt
        assert_eq!(sqn, 4);
        assert_eq!(rpt, 1);
        assert!(idm.scids.ends_with(&[id]));
        assert!(idm.new_cid_if.ends_with(&[(10, 4, 1)]));
        assert!(idm.awaiting_retire_cid_frames.ends_with(&[0]));
    }

    #[test]
    fn ack_in_flight_frames() {
        let mut idm = get_cid_manager(4, 4);

        idm.new_cid_if.push((1, 1, 0));
        idm.new_cid_if.push((3, 2, 0));
        idm.new_cid_if.push((7, 3, 0));

        idm.cid_retirements_if.push((4, 0));
        idm.cid_retirements_if.push((5, 1));

        idm.ack_in_flight(vec![0, 1, 2, 3, 4]);

        assert_eq!(idm.new_cid_if.len(), 1);
        assert_eq!(idm.cid_retirements_if.len(), 1);
    }
}
