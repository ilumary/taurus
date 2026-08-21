use crate::{terror, token::StatelessResetToken};
use octets::varint_len;
use rand::Rng;
use smallvec::SmallVec;
use std::{
    collections::VecDeque,
    fmt,
    hash::{Hash, Hasher},
    time::{Duration, Instant},
};
use tracing::warn;

pub const MAX_CID_SIZE: usize = 0x14;

/// length of the stateless reset token
const SRT_LEN: usize = 0x10;

/// length of every cid we issue
const ISSUED_CID_LEN: usize = 0x08;

/// rotation triggers
const ROTATE_AFTER: Duration = Duration::from_secs(5 * 60);
const ROTATE_AFTER_BYTES: u64 = 16 * 1024 * 1024;

/// inflight limits
const MAX_CID_RETIREMENTS_IN_FLIGHT: u64 = 0x04;
const MAX_NEW_CIDS_IN_FLIGHT: u64 = 0x04;

#[derive(Copy, Clone, Default)]
pub struct Id {
    len: u8,
    bytes: [u8; MAX_CID_SIZE],
}

impl Id {
    #[inline]
    pub fn from_slice(data: &[u8]) -> Self {
        assert!(data.len() <= MAX_CID_SIZE, "cid length exceeds 20 bytes");
        let mut bytes = [0u8; MAX_CID_SIZE];
        bytes[..data.len()].copy_from_slice(data);
        Self {
            len: data.len() as u8,
            bytes,
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn generate_with_length(length: usize) -> Self {
        assert!(length <= MAX_CID_SIZE);
        let mut id = Self {
            len: length as u8,
            bytes: [0u8; MAX_CID_SIZE],
        };
        rand::rng().fill_bytes(&mut id.bytes[..length]);
        id
    }
}

impl PartialEq for Id {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for Id {}

impl PartialOrd for Id {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Id {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl Hash for Id {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for b in self.as_slice() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl core::borrow::Borrow<[u8]> for Id {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<Vec<u8>> for Id {
    #[inline]
    fn from(v: Vec<u8>) -> Self {
        Self::from_slice(&v)
    }
}

/// Tracks both halves of the connection id state machine.
pub struct ConnectionIdManager {
    // ids the peer issued (our dcids)
    dcids: VecDeque<Option<Id>>,
    dcid_srt: VecDeque<Option<StatelessResetToken>>,
    dcid_base: u64,

    // the dcid we currently send with
    dcid_current: Id,
    dcid_current_sqn: u64,
    // highest retire prior to the peer has sent us
    dcid_rpt: u64,
    // number of active dcids
    dcid_active: u64,

    // ids we issued (our scids)
    scids: VecDeque<Option<Id>>,
    scid_srt: VecDeque<Option<StatelessResetToken>>,
    scid_base: u64,
    // retire prior to we advertise
    scid_rpt: u64,
    // active ids for peer
    scid_avail: u64,

    // active_connection_id_limit from the peer
    peer_cid_limit: u64,
    // active_connection_id_limit we advertised
    local_cid_limit: u64,

    // handshake ids, immutable afterwards
    retry_scid: Option<Id>,
    original_dcid: Option<Id>,
    // the scid field of every long header packet
    initial_scid: Id,

    // rotation triggers
    last_issued: Instant,
    recv_byte_counter: u64,
    immediate: bool,

    // dcid sqns awaiting a RETIRE_CONNECTION_ID frame, first send or retransmit
    pending_retire: VecDeque<u64>,
    // scid sqns awaiting a NEW_CONNECTION_ID retransmit
    pending_new: SmallVec<[u64; 4]>,

    // NEW_CONNECTION_ID frames in flight
    nc_inflight: u64,

    // RETIRE_CONNECTION_ID frames in flight
    rc_inflight: u64,
}

impl ConnectionIdManager {
    fn new(
        initial_dcid: Id,
        initial_scid: Id,
        initial_scid_srt: Option<StatelessResetToken>,
        original_dcid: Option<Id>,
        local_cid_limit: u64,
    ) -> Self {
        let mut dcids = VecDeque::with_capacity(4);
        dcids.push_back(Some(initial_dcid));
        let mut dcid_srt = VecDeque::with_capacity(4);
        dcid_srt.push_back(None);

        let mut scids = VecDeque::with_capacity(4);
        scids.push_back(Some(initial_scid));
        let mut scid_srt = VecDeque::with_capacity(4);
        scid_srt.push_back(initial_scid_srt);

        Self {
            dcids,
            dcid_srt,
            dcid_base: 0,
            dcid_current: initial_dcid,
            dcid_current_sqn: 0,
            dcid_rpt: 0,
            dcid_active: 1,
            scids,
            scid_srt,
            scid_base: 0,
            scid_rpt: 0,
            scid_avail: 1,
            peer_cid_limit: 0,
            local_cid_limit,
            retry_scid: None,
            original_dcid,
            initial_scid,
            last_issued: Instant::now(),
            recv_byte_counter: 0,
            immediate: false,
            pending_retire: VecDeque::new(),
            pending_new: SmallVec::new(),
            nc_inflight: 0,
            rc_inflight: 0,
        }
    }

    pub fn as_client(local_cid_limit: u64) -> (Self, Id, Id) {
        let dcid = Id::generate_with_length(ISSUED_CID_LEN);
        let scid = Id::generate_with_length(ISSUED_CID_LEN);

        let cidm = Self::new(dcid, scid, None, Some(dcid), local_cid_limit);

        (cidm, dcid, scid)
    }

    pub fn as_server(
        initial_dcid: Id,
        original_dcid: Id,
        local_cid_limit: u64,
        hmac_reset_token_key: &ring::hmac::Key,
    ) -> (Self, Id, StatelessResetToken) {
        let i_scid = Id::generate_with_length(ISSUED_CID_LEN);
        let srt = StatelessResetToken::new(hmac_reset_token_key, &i_scid);

        let cidm = Self::new(
            initial_dcid,
            i_scid,
            Some(srt),
            Some(original_dcid),
            local_cid_limit,
        );

        (cidm, i_scid, srt)
    }

    /// active_connection_id_limit received from the peer
    #[inline]
    pub fn set_peer_cid_limit(&mut self, limit: u64) {
        self.peer_cid_limit = limit;
    }

    /// client only, replaces the placeholder dcid with the servers choice once
    /// its initial packet arrives
    pub fn replace_initial_dcid(&mut self, connection_id: Id) {
        debug_assert_eq!(self.dcid_base, 0);
        // whichever unsequenced id is currently parked in the slot
        debug_assert_eq!(self.retry_scid.or(self.original_dcid), self.dcids[0]);
        self.set_unsequenced_dcid(connection_id);
    }

    /// client only. the cid from a retry packet carries no sequence number, so
    /// it takes the same slot until the server's initial replaces it.
    pub fn set_retry_scid(&mut self, connection_id: Id) {
        debug_assert_eq!(self.dcid_base, 0);
        self.retry_scid = Some(connection_id);
        self.set_unsequenced_dcid(connection_id);
    }

    /// value to check the peer's retry_source_connection_id transport parameter against
    #[inline]
    pub fn retry_scid(&self) -> Option<&Id> {
        self.retry_scid.as_ref()
    }

    #[inline]
    pub fn original_dcid(&self) -> Option<&Id> {
        self.original_dcid.as_ref()
    }

    #[inline]
    fn set_unsequenced_dcid(&mut self, connection_id: Id) {
        self.dcids[0] = Some(connection_id);
        if self.dcid_current_sqn == 0 {
            self.dcid_current = connection_id;
        }
    }

    #[inline]
    pub fn get_scid(&self) -> &Id {
        &self.initial_scid
    }

    /// the dcid to put in outgoing packets
    #[inline]
    pub fn get_dcid(&self) -> &Id {
        &self.dcid_current
    }

    #[inline]
    pub fn on_bytes_received(&mut self, bytes: u64) {
        self.recv_byte_counter = self.recv_byte_counter.saturating_add(bytes);
    }

    /// forces issuance on the next packet, for path change / nat rebinding /
    /// migration
    #[inline]
    pub fn trigger_immediate(&mut self) {
        self.immediate = true;
    }

    /// handles an incoming NEW_CONNECTION_ID frame
    pub fn handle_new_cid(
        &mut self,
        sqn: u64,
        rpt: u64,
        cid: Id,
        srt: StatelessResetToken,
    ) -> Result<(), terror::Error> {
        if rpt > sqn {
            return Err(terror::Error::quic_transport_error(
                "retire_prior_to is greater than the sequence number",
                terror::QuicTransportError::FrameEncodingError,
            ));
        }

        if cid.is_empty() {
            return Err(terror::Error::quic_transport_error(
                "received zero length connection id",
                terror::QuicTransportError::FrameEncodingError,
            ));
        }

        // below the base means we already retired it
        if sqn < self.dcid_base {
            return Ok(());
        }

        // we must be able to track at least twice the limit we advertised
        if self.pending_retire.len() as u64 > self.local_cid_limit.saturating_mul(2) {
            return Err(terror::Error::quic_transport_error(
                "too many connection ids awaiting retirement",
                terror::QuicTransportError::ConnectionIdLimitError,
            ));
        }

        // cap how far ahead of the base a sequence number may sit
        let window = self.local_cid_limit.saturating_mul(3);
        if sqn - self.dcid_base >= window {
            return Err(terror::Error::quic_transport_error(
                "connection id sequence number too far ahead",
                terror::QuicTransportError::ConnectionIdLimitError,
            ));
        }

        // retire everything below the new watermark before adding the new id
        if rpt > self.dcid_rpt {
            for s in self.dcid_rpt..rpt {
                self.retire_dcid(s);
            }
            self.dcid_rpt = rpt;
        }

        // grow to cover sqn, leaving None in any gap left by reordering
        let idx = (sqn - self.dcid_base) as usize;
        if idx >= self.dcids.len() {
            self.dcids.resize(idx + 1, None);
            self.dcid_srt.resize(idx + 1, None);
        }

        if let Some(known) = self.dcids[idx] {
            // receipt of the same frame again is not an error, but reusing
            // a sequence number for a different id MAY be treated as one
            if known != cid {
                return Err(terror::Error::quic_transport_error(
                    "sequence number reused for a different connection id",
                    terror::QuicTransportError::ProtocolViolation,
                ));
            }
            return Ok(());
        }

        if sqn < self.dcid_rpt {
            // already retired by this or an earlier retire prior to
            if !self.pending_retire.contains(&sqn) {
                self.pending_retire.push_back(sqn);
            }
            return Ok(());
        }

        self.dcids[idx] = Some(cid);
        self.dcid_srt[idx] = Some(srt);
        self.dcid_active += 1;

        // the retirement above can leave us with nothing to send with
        let current_live = self
            .dcid_current_sqn
            .checked_sub(self.dcid_base)
            .and_then(|i| self.dcids.get(i as usize))
            .is_some_and(|slot| slot.is_some());
        if !current_live {
            self.select_dcid();
        }

        // if the active count exceeds what we advertised after adding
        // and retiring, the connection MUST be closed
        if self.dcid_active > self.local_cid_limit {
            return Err(terror::Error::quic_transport_error(
                "peer exceeded local connection id limit",
                terror::QuicTransportError::ConnectionIdLimitError,
            ));
        }

        Ok(())
    }

    /// handles an incoming RETIRE_CONNECTION_ID frame
    pub fn handle_retire_cid(&mut self, sqn: u64) -> Result<Option<Id>, terror::Error> {
        if sqn >= self.scid_base + self.scids.len() as u64 {
            return Err(terror::Error::quic_transport_error(
                "retire cid frame references a connection id we never issued",
                terror::QuicTransportError::ProtocolViolation,
            ));
        }

        // popped off the front already, so this is a duplicate
        let Some(idx) = sqn.checked_sub(self.scid_base) else {
            return Ok(None);
        };
        let idx = idx as usize;

        let Some(id) = self.scids[idx].take() else {
            return Ok(None);
        };
        self.scid_srt[idx] = None;

        // only ids at or above our advertised rpt counted towards what the peer
        // may use after honouring it
        if sqn >= self.scid_rpt {
            self.scid_avail = self.scid_avail.saturating_sub(1);
        }

        // a retired id is never sent again, drop any queued retransmit
        self.pending_new.retain(|s| *s != sqn);

        self.reclaim_scid_front();

        Ok(Some(id))
    }

    /// wire size of the NEW_CONNECTION_ID frame we would send next, or 0 if we
    /// do not want to send one
    pub fn next_new_cid_len(&self, now: Instant) -> usize {
        let sqn = match self.pending_new.last() {
            Some(&sqn) => sqn,
            None if self.nc_inflight < MAX_NEW_CIDS_IN_FLIGHT && self.should_issue_cid(now) => {
                self.scid_base + self.scids.len() as u64
            }
            None => return 0,
        };

        // type + sequence number + retire prior to + length + cid + token
        1 + varint_len(sqn) + varint_len(self.scid_rpt) + 1 + ISSUED_CID_LEN + SRT_LEN
    }

    /// returns (sqn, rpt, id, srt) for the next NEW_CONNECTION_ID frame
    pub fn issue_new_cid(
        &mut self,
        hmac_key: &ring::hmac::Key,
        now: Instant,
    ) -> Option<(u64, u64, Id, StatelessResetToken)> {
        // a lost NEW_CONNECTION_ID is sent again
        if let Some(sqn) = self.pending_new.pop() {
            let slot = sqn
                .checked_sub(self.scid_base)
                .and_then(|i| Some((self.scids.get(i as usize)?, self.scid_srt.get(i as usize)?)));
            return match slot {
                Some((Some(id), Some(srt))) => Some((sqn, self.scid_rpt, *id, *srt)),
                _ => None,
            };
        }

        if !self.should_issue_cid(now) {
            return None;
        }

        let sqn = self.scid_base + self.scids.len() as u64;
        let id = Id::generate_with_length(ISSUED_CID_LEN);
        let srt = StatelessResetToken::new(hmac_key, &id);

        self.scids.push_back(Some(id));
        self.scid_srt.push_back(Some(srt));
        self.scid_avail += 1;

        // we may exceed the peer's limit only if the same frame demands
        // retirement of the excess
        while self.scid_avail > self.peer_cid_limit && self.scid_rpt < sqn {
            let idx = (self.scid_rpt - self.scid_base) as usize;
            if self.scids[idx].is_some() {
                self.scid_avail -= 1;
            }
            self.scid_rpt += 1;
        }

        self.last_issued = now;
        self.recv_byte_counter = 0;
        self.immediate = false;

        Some((sqn, self.scid_rpt, id, srt))
    }

    /// wire size of the next RETIRE_CONNECTION_ID frame, 0 if none is pending
    #[inline]
    pub fn next_retire_cid_len(&self) -> usize {
        match self.pending_retire.front() {
            Some(&sqn) if self.rc_inflight < MAX_CID_RETIREMENTS_IN_FLIGHT => 1 + varint_len(sqn),
            _ => 0,
        }
    }

    pub fn wants_write(&self) -> bool {
        !self.pending_new.is_empty() || !self.pending_retire.is_empty()
    }

    /// pops the sequence number for the next RETIRE_CONNECTION_ID frame
    #[inline]
    pub fn pop_retire_cid(&mut self) -> u64 {
        let sqn = self
            .pending_retire
            .pop_front()
            .expect("pop_retire_cid without a pending retirement");
        debug_assert_ne!(sqn, self.dcid_current_sqn);
        sqn
    }

    pub fn on_new_cid_lost(&mut self, sqn: u64) {
        let Some(idx) = sqn.checked_sub(self.scid_base) else {
            return;
        };

        if self.scids.get(idx as usize).and_then(|s| *s).is_none() {
            return;
        }

        if !self.pending_new.contains(&sqn) {
            self.pending_new.push(sqn);
        }
    }

    #[inline]
    pub fn ack_new_connection_id_frame(&mut self) {
        self.nc_inflight = self.nc_inflight.saturating_sub(1);
    }

    #[inline]
    pub fn ack_retire_connection_id_frame(&mut self) {
        self.rc_inflight = self.rc_inflight.saturating_sub(1);
    }

    #[inline]
    pub fn add_new_connection_id_frame(&mut self) {
        self.nc_inflight += 1;
    }

    #[inline]
    pub fn add_retire_connection_id_frame(&mut self) {
        self.rc_inflight += 1;
    }

    pub fn on_retire_cid_lost(&mut self, sqn: u64) {
        if !self.pending_retire.contains(&sqn) {
            self.pending_retire.push_front(sqn);
        }
    }

    /// true if one of four triggers fires: we are below the peer's limit, the
    /// rotation timer expired, enough bytes arrived, or a path change asked for it
    pub fn should_issue_cid(&self, now: Instant) -> bool {
        if self.scid_avail < self.peer_cid_limit {
            return true;
        }

        if self.scid_base < self.scid_rpt || self.peer_cid_limit == 0 {
            return false;
        }

        self.immediate
            || self.recv_byte_counter >= ROTATE_AFTER_BYTES
            || now.duration_since(self.last_issued) >= ROTATE_AFTER
    }

    fn retire_dcid(&mut self, sqn: u64) {
        let Some(idx) = sqn.checked_sub(self.dcid_base) else {
            return;
        };

        let idx = idx as usize;
        let Some(slot) = self.dcids.get_mut(idx) else {
            return;
        };

        if slot.take().is_none() {
            return;
        }

        self.dcid_srt[idx] = None;
        self.dcid_active = self.dcid_active.saturating_sub(1);
        self.pending_retire.push_back(sqn);

        if self.dcid_current_sqn == sqn {
            self.select_dcid();
        }
        self.reclaim_dcid_front();
    }

    fn select_dcid(&mut self) {
        match self
            .dcids
            .iter()
            .enumerate()
            .find_map(|(i, slot)| (*slot).map(|id| (i as u64, id)))
        {
            Some((i, id)) => {
                self.dcid_current_sqn = self.dcid_base + i;
                self.dcid_current = id;
            }
            None => warn!("peer retired every connection id without a replacement"),
        }
    }

    #[inline]
    fn reclaim_dcid_front(&mut self) {
        while matches!(self.dcids.front(), Some(None)) {
            self.dcids.pop_front();
            self.dcid_srt.pop_front();
            self.dcid_base += 1;
        }
    }

    #[inline]
    fn reclaim_scid_front(&mut self) {
        while matches!(self.scids.front(), Some(None)) {
            self.scids.pop_front();
            self.scid_srt.pop_front();
            self.scid_base += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> ring::hmac::Key {
        ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[0xAB; 32])
    }

    fn srt_of(id: &Id) -> StatelessResetToken {
        StatelessResetToken::new(&test_key(), id)
    }

    fn manager(num_dcids: u64, num_scids: u64) -> ConnectionIdManager {
        assert!(num_dcids >= 1 && num_scids >= 1);
        let (mut m, _, _) = ConnectionIdManager::as_client(4);
        m.set_peer_cid_limit(4);

        for sqn in 1..num_dcids {
            let id = Id::generate_with_length(8);
            m.handle_new_cid(sqn, 0, id, srt_of(&id)).unwrap();
        }

        for _ in 1..num_scids {
            let id = Id::generate_with_length(8);
            m.scids.push_back(Some(id));
            m.scid_srt.push_back(Some(srt_of(&id)));
            m.scid_avail += 1;
        }
        m
    }

    #[test]
    fn connection_establishment_client_to_server() {
        let (mut c, c_initial_dcid, c_initial_scid) = ConnectionIdManager::as_client(4);
        let (s, s_initial_scid, _) =
            ConnectionIdManager::as_server(c_initial_scid, c_initial_dcid, 4, &test_key());

        assert_eq!(c_initial_scid, *s.get_dcid());
        assert_eq!(s_initial_scid, *s.get_scid());

        c.replace_initial_dcid(s_initial_scid);

        assert_eq!(s_initial_scid, *c.get_dcid());
        assert_eq!(c_initial_scid, *c.get_scid());
    }

    #[test]
    fn scid_stays_the_initial_one_across_rotation() {
        // the scid field must not change during the handshake even if we issue new ids
        let mut m = manager(1, 1);
        let initial = *m.get_scid();
        m.peer_cid_limit = 4;

        let (_, _, id, _) = m.issue_new_cid(&test_key(), Instant::now()).unwrap();

        assert_ne!(initial, id);
        assert_eq!(initial, *m.get_scid());
    }

    #[test]
    fn retry_scid_takes_the_unsequenced_slot_until_the_server_initial() {
        let (mut c, c_initial_dcid, _) = ConnectionIdManager::as_client(4);
        assert_eq!(*c.get_dcid(), c_initial_dcid);
        assert!(c.retry_scid().is_none());

        // a retry replaces the dcid, but carries no sequence number
        let retry = Id::generate_with_length(8);
        c.set_retry_scid(retry);
        assert_eq!(*c.get_dcid(), retry);
        assert_eq!(c.retry_scid(), Some(&retry));
        assert_eq!(c.dcids.len(), 1);

        // the server initial cid then supplies the id that really is sqn 0
        let server_scid = Id::generate_with_length(8);
        c.replace_initial_dcid(server_scid);
        assert_eq!(*c.get_dcid(), server_scid);
        assert_eq!(c.dcid_current_sqn, 0);
        assert_eq!(c.retry_scid(), Some(&retry));
    }

    #[test]
    fn retirement_queue_is_bounded() {
        let mut m = manager(1, 1);
        // a peer churning ids faster than we drain the queue must not be able
        // to grow it without bound
        let budget = m.local_cid_limit * 2;
        for sqn in 1..=budget + 4 {
            let id = Id::generate_with_length(8);
            if m.handle_new_cid(sqn, sqn, id, srt_of(&id)).is_err() {
                assert!(m.pending_retire.len() as u64 > budget);
                return;
            }
        }
        panic!("retirement queue grew past the limit without erroring");
    }

    #[test]
    fn new_cid_is_stored_at_its_sequence_number() {
        let mut m = manager(1, 1);
        let ncid = Id::generate_with_length(8);

        assert!(m.handle_new_cid(1, 0, ncid, srt_of(&ncid)).is_ok());
        assert_eq!(m.dcids[1], Some(ncid));
        assert_eq!(m.dcid_srt[1].unwrap().token, srt_of(&ncid).token);
        assert_eq!(m.dcid_active, 2);
        assert_eq!(m.dcid_current_sqn, 0);
    }

    #[test]
    fn new_cid_rejects_rpt_above_sqn() {
        let mut m = manager(4, 1);
        let ncid = Id::generate_with_length(8);

        let r = m.handle_new_cid(4, 5, ncid, srt_of(&ncid));

        assert_eq!(
            r.unwrap_err().kind(),
            terror::QuicTransportError::FrameEncodingError as u64
        );
        assert_eq!(m.dcids.len(), 4);
        assert_eq!(m.dcid_rpt, 0);
        assert!(m.pending_retire.is_empty());
    }

    #[test]
    fn new_cid_rejects_zero_length_id() {
        let mut m = manager(1, 1);
        let empty = Id::default();

        let r = m.handle_new_cid(1, 0, empty, srt_of(&empty));

        assert_eq!(
            r.unwrap_err().kind(),
            terror::QuicTransportError::FrameEncodingError as u64
        );
    }

    #[test]
    fn new_cid_over_local_limit_is_an_error() {
        let mut m = manager(4, 1);
        let ncid = Id::generate_with_length(8);

        let r = m.handle_new_cid(4, 0, ncid, srt_of(&ncid));

        assert_eq!(
            r.unwrap_err().kind(),
            terror::QuicTransportError::ConnectionIdLimitError as u64
        );
    }

    #[test]
    fn new_cid_at_the_limit_with_retirement_is_accepted() {
        // lets the peer exceed the limit when the same frame retires the excess
        let mut m = manager(4, 1);
        let ncid = Id::generate_with_length(8);

        assert!(m.handle_new_cid(4, 1, ncid, srt_of(&ncid)).is_ok());
        assert_eq!(m.dcids[4 - m.dcid_base as usize], Some(ncid));
        assert_eq!(m.dcid_rpt, 1);
        assert_eq!(m.dcid_active, 4);
        assert_eq!(m.pending_retire, [0]);
        assert_eq!(m.dcid_current_sqn, 1);
    }

    #[test]
    fn new_cid_can_retire_every_earlier_id() {
        let mut m = manager(4, 1);
        let ncid = Id::generate_with_length(8);

        assert!(m.handle_new_cid(4, 4, ncid, srt_of(&ncid)).is_ok());
        assert_eq!(m.dcid_rpt, 4);
        assert_eq!(m.dcid_active, 1);
        assert_eq!(m.pending_retire, [0, 1, 2, 3]);
        assert_eq!(m.dcid_base, 4);
        assert_eq!(m.dcid_current_sqn, 4);
        assert_eq!(*m.get_dcid(), ncid);
    }

    #[test]
    fn reordered_new_cid_leaves_a_gap() {
        let mut m = manager(1, 1);
        let third = Id::generate_with_length(8);
        let second = Id::generate_with_length(8);

        assert!(m.handle_new_cid(2, 0, third, srt_of(&third)).is_ok());
        assert_eq!(m.dcids[1], None);
        assert_eq!(m.dcids[2], Some(third));
        assert_eq!(m.dcid_active, 2);

        assert!(m.handle_new_cid(1, 0, second, srt_of(&second)).is_ok());
        assert_eq!(m.dcids[1], Some(second));
        assert_eq!(m.dcid_active, 3);
    }

    #[test]
    fn duplicate_new_cid_is_ignored_but_a_changed_id_is_not() {
        let mut m = manager(1, 1);
        let ncid = Id::generate_with_length(8);

        assert!(m.handle_new_cid(1, 0, ncid, srt_of(&ncid)).is_ok());
        // the same frame again must not be an error
        assert!(m.handle_new_cid(1, 0, ncid, srt_of(&ncid)).is_ok());
        assert_eq!(m.dcid_active, 2);

        let other = Id::generate_with_length(8);
        let r = m.handle_new_cid(1, 0, other, srt_of(&other));
        assert_eq!(
            r.unwrap_err().kind(),
            terror::QuicTransportError::ProtocolViolation as u64
        );
    }

    #[test]
    fn new_cid_below_the_base() {
        let mut m = manager(2, 1);
        let high = Id::generate_with_length(8);

        assert!(m.handle_new_cid(2, 2, high, srt_of(&high)).is_ok());
        assert_eq!(m.pending_retire, [0, 1]);
        assert_eq!(m.dcid_base, 2);
        m.pending_retire.clear();

        let late = Id::generate_with_length(8);
        assert!(m.handle_new_cid(1, 0, late, srt_of(&late)).is_ok());
        assert!(m.pending_retire.is_empty());
        assert_eq!(m.dcid_active, 1);
    }

    #[test]
    fn new_cid_in_a_gap_below_retire_prior_to_is_retired() {
        let mut m = manager(1, 1);
        let high = Id::generate_with_length(8);
        assert!(m.handle_new_cid(3, 2, high, srt_of(&high)).is_ok());
        assert_eq!(m.pending_retire, [0]);
        assert_eq!(m.dcid_base, 1);

        let late = Id::generate_with_length(8);
        assert!(m.handle_new_cid(1, 0, late, srt_of(&late)).is_ok());
        assert_eq!(m.pending_retire, [0, 1]);
        assert_eq!(m.dcid_active, 1);
        assert_eq!(m.dcid_current_sqn, 3);
    }

    #[test]
    fn absurd_sequence_number_does_not_allocate() {
        let mut m = manager(1, 1);
        let ncid = Id::generate_with_length(8);

        let r = m.handle_new_cid(u64::MAX / 2, 0, ncid, srt_of(&ncid));

        assert_eq!(
            r.unwrap_err().kind(),
            terror::QuicTransportError::ConnectionIdLimitError as u64
        );
        assert_eq!(m.dcids.len(), 1);
    }

    #[test]
    fn retire_cid() {
        let mut m = manager(1, 4);
        let id2 = m.scids[2].unwrap();
        assert_eq!(m.handle_retire_cid(2).unwrap(), Some(id2));
        assert!(m.scids[0].is_some());
        assert!(m.scids[1].is_some());
        assert_eq!(m.scids[2], None);
        assert!(m.scids[3].is_some());
        assert_eq!(m.scid_avail, 3);
        assert_eq!(m.scid_base, 0);

        // accepts the highest issued sequence_number
        let mut m = manager(1, 4);
        assert!(m.handle_retire_cid(3).unwrap().is_some());
        assert_eq!(m.scid_avail, 3);

        // rejects an unissued sequence number
        let mut m = manager(1, 4);
        let r = m.handle_retire_cid(4);
        assert_eq!(
            r.unwrap_err().kind(),
            terror::QuicTransportError::ProtocolViolation as u64
        );
        assert_eq!(m.scid_avail, 4);

        // idempotence
        let mut m = manager(1, 4);
        assert!(m.handle_retire_cid(2).unwrap().is_some());
        assert_eq!(m.handle_retire_cid(2).unwrap(), None);
        assert_eq!(m.scid_avail, 3);

        // reclaims the ring front
        let mut m = manager(1, 4);
        assert!(m.handle_retire_cid(1).unwrap().is_some());
        assert_eq!(m.scid_base, 0);
        assert!(m.handle_retire_cid(0).unwrap().is_some());
        assert_eq!(m.scid_base, 2);
        assert_eq!(m.scids.len(), 2);
        assert_eq!(m.handle_retire_cid(0).unwrap(), None);
    }

    #[test]
    fn issue_tops_up_to_the_peer_limit_then_stops() {
        let mut m = manager(1, 1);
        m.set_peer_cid_limit(3);
        let now = Instant::now();
        let key = test_key();

        for expected_sqn in 1..3 {
            let (sqn, rpt, id, srt) = m.issue_new_cid(&key, now).unwrap();
            assert_eq!(sqn, expected_sqn);
            assert_eq!(rpt, 0);
            assert!(srt.verify(&key, &id));
            assert_eq!(m.scids[sqn as usize], Some(id));
        }

        assert_eq!(m.scid_avail, 3);
        assert!(!m.should_issue_cid(now));
        assert!(m.issue_new_cid(&key, now).is_none());
        assert_eq!(m.next_new_cid_len(now), 0);
    }

    #[test]
    fn issue_before_transport_parameters_is_suppressed() {
        // peer_cid_limit is 0 until the peer's transport parameters arrive
        let (mut m, _, _) = ConnectionIdManager::as_client(4);
        let now = Instant::now();

        assert!(!m.should_issue_cid(now));
        assert!(m.issue_new_cid(&test_key(), now).is_none());
        assert!(!m.should_issue_cid(now + ROTATE_AFTER * 2));
    }

    #[test]
    fn time_trigger_forces_rotation_and_raises_retire_prior_to() {
        let mut m = manager(1, 4);
        m.set_peer_cid_limit(4);
        let now = Instant::now();
        let key = test_key();

        assert!(!m.should_issue_cid(now));

        let later = now + ROTATE_AFTER;
        let (sqn, rpt, id, _) = m.issue_new_cid(&key, later).unwrap();

        assert_eq!(sqn, 4);
        assert_eq!(rpt, 1);
        assert_eq!(m.scids[4], Some(id));
        assert_eq!(m.scid_avail, 4);
        assert!(!m.should_issue_cid(later + ROTATE_AFTER));

        assert!(m.handle_retire_cid(0).unwrap().is_some());
        assert_eq!(m.scid_base, 1);
        assert!(m.should_issue_cid(later + ROTATE_AFTER));
    }

    #[test]
    fn byte_and_immediate_triggers() {
        let mut m = manager(1, 4);
        m.set_peer_cid_limit(4);
        let now = Instant::now();

        assert!(!m.should_issue_cid(now));
        m.on_bytes_received(ROTATE_AFTER_BYTES);
        assert!(m.should_issue_cid(now));

        assert!(m.issue_new_cid(&test_key(), now).is_some());
        assert_eq!(m.recv_byte_counter, 0);

        m.trigger_immediate();
        assert!(m.immediate);
        assert!(!m.should_issue_cid(now));
        assert!(m.handle_retire_cid(0).unwrap().is_some());
        assert!(m.should_issue_cid(now));
    }

    #[test]
    fn new_cid_frame_length() {
        let mut m = manager(1, 1);
        m.set_peer_cid_limit(4);
        let now = Instant::now();

        let len = m.next_new_cid_len(now);
        let (sqn, rpt, id, _) = m.issue_new_cid(&test_key(), now).unwrap();

        // type + sqn + rpt + length byte + cid + token
        let encoded = 1 + varint_len(sqn) + varint_len(rpt) + 1 + id.len() + SRT_LEN;
        assert_eq!(len, encoded);
    }

    #[test]
    fn retire_frame_length() {
        let mut m = manager(1, 1);
        assert_eq!(m.next_retire_cid_len(), 0);

        let high = Id::generate_with_length(8);
        m.handle_new_cid(1, 1, high, srt_of(&high)).unwrap();

        // type byte + varint
        assert_eq!(m.next_retire_cid_len(), 1 + varint_len(0));
        assert_eq!(m.pop_retire_cid(), 0);
        assert_eq!(m.next_retire_cid_len(), 0);
    }

    #[test]
    fn lost_new_cid_is_resent_with_the_same_id() {
        let mut m = manager(1, 1);
        m.set_peer_cid_limit(4);
        let now = Instant::now();
        let key = test_key();

        let (sqn, _, id, srt) = m.issue_new_cid(&key, now).unwrap();
        while m.issue_new_cid(&key, now).is_some() {}

        m.on_new_cid_lost(sqn);
        assert_eq!(
            m.next_new_cid_len(now),
            1 + varint_len(sqn) + varint_len(m.scid_rpt) + 1 + 8 + SRT_LEN
        );

        let (rsqn, _, rid, rsrt) = m.issue_new_cid(&key, now).unwrap();

        assert_eq!(rsqn, sqn);
        assert_eq!(rid, id);
        assert_eq!(rsrt.token, srt.token);
        assert!(m.pending_new.is_empty());
    }

    #[test]
    fn lost_new_cid_is_not_resent_once_retired() {
        let mut m = manager(1, 1);
        m.set_peer_cid_limit(4);
        let now = Instant::now();
        let key = test_key();

        let (sqn, _, _, _) = m.issue_new_cid(&key, now).unwrap();
        m.on_new_cid_lost(sqn);
        assert_eq!(m.pending_new.as_slice(), &[sqn]);

        assert!(m.handle_retire_cid(sqn).unwrap().is_some());
        assert!(m.pending_new.is_empty());

        m.on_new_cid_lost(sqn);
        assert!(m.pending_new.is_empty());
    }

    #[test]
    fn lost_new_cid_carries_the_current_retire_prior_to() {
        let mut m = manager(1, 4);
        m.set_peer_cid_limit(4);
        let now = Instant::now();
        let key = test_key();

        let (sqn, rpt, _, _) = m.issue_new_cid(&key, now + ROTATE_AFTER).unwrap();
        assert_eq!(rpt, 1);

        m.on_new_cid_lost(1);
        let (rsqn, rrpt, _, _) = m.issue_new_cid(&key, now).unwrap();
        assert_eq!(rsqn, 1);
        assert_eq!(rrpt, 1);
        assert_ne!(rsqn, sqn);
    }

    #[test]
    fn lost_retire_cid_is_requeued_ahead_of_the_rest() {
        let mut m = manager(1, 1);
        let high = Id::generate_with_length(8);
        m.handle_new_cid(2, 2, high, srt_of(&high)).unwrap();
        assert_eq!(m.pending_retire, [0]);

        assert_eq!(m.pop_retire_cid(), 0);
        assert_eq!(m.next_retire_cid_len(), 0);

        let late = Id::generate_with_length(8);
        m.handle_new_cid(1, 0, late, srt_of(&late)).unwrap();
        assert_eq!(m.pending_retire, [1]);

        m.on_retire_cid_lost(0);
        assert_eq!(m.pending_retire, [0, 1]);

        m.on_retire_cid_lost(0);
        assert_eq!(m.pending_retire, [0, 1]);
    }

    #[test]
    fn retired_dcid_is_never_the_one_we_send_with() {
        // RETIRE_CONNECTION_ID must not name the dcid of its own packet
        let mut m = manager(3, 1);
        assert_eq!(m.dcid_current_sqn, 0);

        let ncid = Id::generate_with_length(8);
        m.handle_new_cid(3, 2, ncid, srt_of(&ncid)).unwrap();

        assert_eq!(m.dcid_current_sqn, 2);
        while m.next_retire_cid_len() > 0 {
            assert_ne!(m.pop_retire_cid(), m.dcid_current_sqn);
        }
    }
}
