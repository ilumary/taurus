use std::{
    net::SocketAddr,
    time::Instant
};

use smallvec::SmallVec;

use crate::{
    cc::{CongestionController, UnlimitedWindow, SentPacket, SentFrame},
    packet::AckFrame
};

pub const MIN_DATAGRAM: usize = 1200;

const MAX_IN_FLIGHT_CHALLENGES: usize = 8;
const MAX_RECV_CHALLENGES: usize = 3;

struct Validation {
    /// random challenge data
    challenge: [u8; 8],

    /// whether the challenge datagram was/will be expanded to `MIN_DATAGRAM`
    expanded: bool,

    /// a PATH_CHALLENGE is queued to be written into the next packet
    pending: bool,

    /// abandon validation once `now >= deadline`
    deadline: Instant,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PathState {
    /// unknown, no path validation has happened
    Unvalidated,

    /// the path is currently being validated
    Validating,

    /// reachable, but unconfirmed mtu
    ValidatingMtu,

    /// the path is validated
    Validated,

    /// validation failed, the path is unusable
    Failed,
}

/// result of driving every path's timers via [`Paths::on_timeout`]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PathEvent {
    /// no state change relevant to the connection
    None,

    /// the active path was migrated to this path index
    Migrated(usize),

    /// the active path failed and no validated alternative exists. the
    /// connection MAY close with NO_VIABLE_PATH
    NoViablePath,
}

/// effect of feeding a PATH_RESPONSE payload to a path
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ResponseOutcome {
    /// no outstanding challenge on this path matched the payload
    Unmatched,

    /// The path is reachable but its base MTU is not yet confirmed; an expanded
    /// PATH_CHALLENGE is now requested (§8.2.3).
    Reachable,

    /// The path is now fully validated (reachable + base MTU confirmed).
    Validated,

    /// Matched a leftover challenge on an already-validated path (cleanup only).
    Stale,
}

/// A PATH_CHALLENGE we have sent and are awaiting a response for (§8.2.1).
struct InFlightChallenge {
    /// The unpredictable payload that must be echoed back.
    data: [u8; 8],
    /// Size of the datagram it was sent in; `>= MIN_DATAGRAM` confirms the MTU.
    datagram_len: usize,
    sent_at: Instant,
}

/// represents a single path on which communication happens
pub struct Path {
    /// address tuple
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,

    /// current path state
    state: PathState,

    /// a fresh PATH_CHALLENGE should be emitted on this path
    validation_requested: bool,
    /// challenges sent that are awaiting a response
    in_flight_challenges: SmallVec<[InFlightChallenge; 4]>,
    /// abandon the current validation phase at this time, if no answer arrives
    validation_deadline: Option<Instant>,
    /// PATH_CHALLENGE payloads received here, awaiting a PATH_RESPONSE echo on
    /// this same path. bounded. at most one response per challenge.
    received_challenges: SmallVec<[[u8; 8]; 4]>,


    /// current validated mtu for this path
    mtu: usize,
    /// candidate size of an in-flight PMTU probe, if any
    //mtu_probe: Option<usize>,
    /// (space, packet number) of the in-flight PMTU probe
    //mtu_probe_pn: Option<(usize, u64)>,

    // TODO make configurable per path
    /// per-path cc
    cc: CongestionController<UnlimitedWindow>,

    // TODO pacing

    /// bookkeeping
    bytes_received: u64,
    bytes_sent: u64,

    last_recv: Option<Instant>,
    last_sent: Option<Instant>,
}

impl Path {
    fn new(local_addr: SocketAddr, peer_addr: SocketAddr) -> Self {
        Path {
            local_addr,
            peer_addr,
            state: PathState::Unvalidated,
            validation_requested: false,
            in_flight_challenges: SmallVec::new(),
            validation_deadline: None,
            received_challenges: SmallVec::new(),
            mtu: MIN_DATAGRAM,
            //mtu_probe: None,
            //mtu_probe_pn: None,
            cc: CongestionController::new(UnlimitedWindow),
            bytes_received: 0,
            bytes_sent: 0,
            last_recv: None,
            last_sent: None,
        }
    }

    pub fn on_packet_sent(
        &mut self,
        pn: u64,
        space: usize,
        size: usize,
        ack_eliciting: bool,
        now: Instant,
        frames: SmallVec<[SentFrame; 2]>,
    ) {
        self.bytes_sent = self.bytes_sent.saturating_add(size as u64);
        self.last_sent = Some(now);
        self.cc.on_packet_sent(space, pn, size, now, ack_eliciting, frames);
    }

    pub fn on_datagram_received(&mut self, size: usize, now: Instant) {
        self.bytes_received = self.bytes_received.saturating_add(size as u64);
        self.last_recv = Some(now);
    }

    pub fn on_ack_received(
        &mut self,
        space: usize,
        ack: &AckFrame,
        now: Instant,
    ) -> (Vec<SentPacket>, Vec<SentPacket>) {
        let (acked, lost) = self.cc.on_ack_received(space, ack, now);

        // resolve an in-flight PMTU probe
        // TODO replace with Optional on SentPacket maybe which tracks the values
        // because saerching every acked and lost packet for PMTU probe is a bit wasteful
        /*if let Some((pspace, ppn)) = self.mtu_probe_pn {
            if pspace == space {
                if acked.iter().any(|p| p.0 == ppn) {
                    if let Some(size) = self.mtu_probe.take() {
                        if size > self.mtu {
                            self.mtu = size;
                        }
                    }
                    self.mtu_probe_pn = None;
                } else if lost.iter().any(|p| p.0 == ppn) {
                    self.mtu_probe = None;
                    self.mtu_probe_pn = None;
                }
            }
        }*/

        (acked, lost)
    }

    /// loss-detection deadline for this path
    pub fn loss_detection_timeout(&self) -> Option<Instant> {
        self.cc.loss_detection_timeout()
    }

    /// drive the cc's loss timer. on a PTO while validating, a fresh PATH_CHALLENGE is
    /// requested so the probe carries new data
    pub fn on_loss_detection_timeout(&mut self, now: Instant) -> Vec<SentPacket> {
        let lost = self.cc.on_loss_detection_timeout(now);
        if lost.is_empty() && self.is_validating() {
            self.validation_requested = true;
        }
        lost
    }

    /// ask for a (fresh) PATH_CHALLENGE to be emitted on this path
    pub fn request_validation(&mut self) {
        if self.state != PathState::Failed {
            self.validation_requested = true;
        }
    }

    /// record a PATH_CHALLENGE just emitted in a datagram of `datagram_len`
    /// bytes. `data` must be unpredictable and unique per call
    pub fn add_challenge_sent(&mut self, data: [u8; 8], datagram_len: usize, now: Instant) {
        if self.in_flight_challenges.len() >= MAX_IN_FLIGHT_CHALLENGES {
            self.in_flight_challenges.remove(0);
        }
        self.in_flight_challenges.push(InFlightChallenge {
            data,
            datagram_len,
            sent_at: now,
        });
        self.validation_requested = false;

        if matches!(self.state, PathState::Unvalidated) {
            self.state = PathState::Validating;
        }
        if self.is_validating() && self.validation_deadline.is_none() {
            // abandon after 3 × PTO
            self.validation_deadline = Some(now + self.cc.pto().saturating_mul(3));
        }
    }

    pub fn close_timeout(&self, now: Instant) -> Instant {
        now + self.cc.pto().saturating_mul(3)
    }

    /// mark the path validated without a challenge
    pub fn mark_validated(&mut self) {
        self.state = PathState::Validated;
        self.validation_requested = false;
        self.validation_deadline = None;
        self.in_flight_challenges.clear();
    }

    /// a PATH_CHALLENGE arrived on this path, queue the echo. the
    /// PATH_RESPONSE must later be sent *on this same path*
    pub fn on_path_challenge(&mut self, data: [u8; 8]) {
        if self.received_challenges.len() < MAX_RECV_CHALLENGES
            && !self.received_challenges.contains(&data)
        {
            self.received_challenges.push(data);
        }
    }

    /// feed a received PATH_RESPONSE payload to this path
    pub fn on_response_received(&mut self, data: [u8; 8]) -> ResponseOutcome {
        let Some(pos) = self.in_flight_challenges.iter().position(|c| c.data == data) else {
            return ResponseOutcome::Unmatched;
        };
        let mtu_ok = self.in_flight_challenges.remove(pos).datagram_len >= MIN_DATAGRAM;

        match self.state {
            PathState::Validating => {
                if mtu_ok {
                    self.transition_validated();
                    ResponseOutcome::Validated
                } else {
                    // reachable, MTU unconfirmed
                    self.state = PathState::ValidatingMtu;
                    self.validation_requested = true;
                    self.validation_deadline = None;
                    ResponseOutcome::Reachable
                }
            }
            PathState::ValidatingMtu => {
                if mtu_ok {
                    self.transition_validated();
                    ResponseOutcome::Validated
                } else {
                    ResponseOutcome::Reachable
                }
            }
            _ => ResponseOutcome::Stale,
        }
    }

    fn transition_validated(&mut self) {
        self.state = PathState::Validated;
        self.validation_requested = false;
        self.validation_deadline = None;
    }

    /// check the abandon timer. returns `true` if the path just failed.
    pub fn on_validation_timeout(&mut self, now: Instant) -> bool {
        if self.is_validating() {
            if let Some(deadline) = self.validation_deadline {
                if now >= deadline {
                    self.state = PathState::Failed;
                    self.validation_requested = false;
                    self.validation_deadline = None;
                    self.in_flight_challenges.clear();
                    return true;
                }
            }
        }
        false
    }

    /// next PATH_RESPONSE payload to write on this path, if any
    pub fn poll_response(&mut self) -> Option<[u8; 8]> {
        self.received_challenges.pop()
    }

    /// record a PMTU probe of `size` bytes just sent as packet `pn` in `space`
    pub fn on_mtu_probe_sent(&mut self, size: usize, space: usize, pn: u64) {
        todo!()
    }

    /// whether reachability is confirmed
    #[inline]
    fn reachable(&self) -> bool {
        self.state == PathState::Validated || self.state == PathState::ValidatingMtu
    }

    /// Max size of the next datagram allowed on this path.
    pub fn send_budget(&self) -> usize {
        if self.reachable() {
            self.mtu
        } else {
            let allowance = self
                .bytes_received
                .saturating_mul(3)
                .saturating_sub(self.bytes_sent) as usize;
            self.mtu.min(allowance)
        }
    }

    /// ack-eliciting bytes allowed in flight
    #[inline]
    pub fn cwnd_available(&self) -> usize {
        self.cc.available_window()
    }

    #[inline]
    pub fn is_validated(&self) -> bool {
        self.state == PathState::Validated
    }

    #[inline]
    pub fn is_validating(&self) -> bool {
        self.state == PathState::Validating || self.state == PathState::ValidatingMtu
    }

    #[inline]
    pub fn is_failed(&self) -> bool {
        self.state == PathState::Failed
    }

    #[inline]
    pub fn validation_requested(&self) -> bool {
        self.validation_requested
    }

    /// whether the connection should emit a probe on this path
    /// TODO: PMTUD scheduling
    #[inline]
    pub fn probing_required(&self) -> bool {
        self.validation_requested
    }

    #[inline]
    pub fn needs_mtu_validation(&self) -> bool {
        self.state == PathState::ValidatingMtu
    }

    #[inline]
    pub fn has_pending_response(&self) -> bool {
        !self.received_challenges.is_empty()
    }

    #[inline]
    pub fn last_active(&self) -> Option<Instant> {
        match (self.last_recv, self.last_sent) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    }

    pub fn is_idle(&self, now: Instant, idle: std::time::Duration) -> bool {
        match self.last_active() {
            Some(t) => now.saturating_duration_since(t) >= idle,
            None => true,
        }
    }

    pub fn next_timeout(&self) -> Option<Instant> {
        match (self.validation_deadline, self.loss_detection_timeout()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, None) => a,
            (None, b) => b,
        }
    }

    #[inline]
    pub fn cc(&self) -> &CongestionController<UnlimitedWindow> {
        &self.cc
    }

    #[inline]
    pub fn cc_mut(&mut self) -> &mut CongestionController<UnlimitedWindow> {
        &mut self.cc
    }
}

/// manage all paths on a connection
pub struct Paths {
    /// keeps track of paths, 2 should be enough for most connections
    paths: SmallVec<[Path; 2]>,

    /// max number of paths allowed
    max_paths: usize,

    /// active path by index
    active: usize,

    /// if this is a server
    is_server: bool,
}

impl Paths {
    /// create the path set with its initial (active) path. The initial path
    /// starts `Unvalidated`. call `active_mut().mark_validated()` once the
    /// handshake confirms the peer address
    pub fn new(local: SocketAddr, peer: SocketAddr, is_server: bool, max_paths: usize) -> Self {
        let mut paths = SmallVec::new();
        paths.push(Path::new(local, peer));
        Paths {
            paths,
            max_paths: max_paths.max(1),
            active: 0,
            is_server,
        }
    }

    #[inline]
    pub fn active(&self) -> &Path {
        &self.paths[self.active]
    }

    #[inline]
    pub fn active_mut(&mut self) -> &mut Path {
        &mut self.paths[self.active]
    }

    #[inline]
    pub fn active_idx(&self) -> usize {
        self.active
    }

    #[inline]
    pub fn is_server(&self) -> bool {
        self.is_server
    }

    #[inline]
    pub fn get(&self, idx: usize) -> Option<&Path> {
        self.paths.get(idx)
    }

    #[inline]
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut Path> {
        self.paths.get_mut(idx)
    }

    pub fn index_of(&self, local: SocketAddr, peer: SocketAddr) -> Option<usize> {
        self.paths
            .iter()
            .position(|p| p.local_addr == local && p.peer_addr == peer)
    }

    pub fn path_mut(&mut self, local: SocketAddr, peer: SocketAddr) -> Option<&mut Path> {
        match self.index_of(local, peer) {
            Some(i) => Some(&mut self.paths[i]),
            None => None,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Path> {
        self.paths.iter()
    }

    pub fn add_path(&mut self, local: SocketAddr, peer: SocketAddr) -> Option<usize> {
        if let Some(i) = self.index_of(local, peer) {
            return Some(i);
        }
        if self.paths.len() >= self.max_paths {
            let evict = self.find_evictable()?;
            self.paths[evict] = Path::new(local, peer);
            return Some(evict);
        }
        self.paths.push(Path::new(local, peer));
        Some(self.paths.len() - 1)
    }

    /// route a received PATH_RESPONSE to whichever path it validates,
    /// regardless of arrival path. returns the path index and what changed
    pub fn on_path_response(&mut self, data: [u8; 8]) -> Option<(usize, ResponseOutcome)> {
        for (i, p) in self.paths.iter_mut().enumerate() {
            match p.on_response_received(data) {
                ResponseOutcome::Unmatched => continue,
                outcome => return Some((i, outcome)),
            }
        }
        None
    }

    /// force the active path to `idx`
    pub fn migrate_to(&mut self, idx: usize) -> bool {
        if idx < self.paths.len() && idx != self.active {
            self.active = idx;
            true
        } else {
            false
        }
    }

    /// re-pick the active path from the others: if the current active path is no
    /// longer validated, switch to the most-recently-active validated path.
    /// returns whether the active path changed
    /*pub fn select_active(&mut self) -> bool {
        if self.paths[self.active].is_validated() {
            return false;
        }
        if let Some(i) = self.best_validated() {
            if i != self.active {
                self.active = i;
                return true;
            }
        }
        false
    }*/

    /// check validation timers across every path. Handles abandonment (§8.2.4)
    /// and, if the active path failed, migration to a validated alternative or a
    /// NO_VIABLE_PATH signal.
    pub fn on_timeout(&mut self, now: Instant) -> PathEvent {
        let mut active_failed = false;
        for (i, p) in self.paths.iter_mut().enumerate() {
            if p.on_validation_timeout(now) && i == self.active {
                active_failed = true;
            }
        }
        if active_failed {
            if let Some(i) = self.best_validated() {
                self.active = i;
                return PathEvent::Migrated(i);
            }
            return PathEvent::NoViablePath;
        }
        PathEvent::None
    }

    /// remove paths that are no longer useful: failed paths, and idle paths that
    /// are neither active nor mid-validation
    pub fn prune(&mut self, now: Instant, idle: std::time::Duration) {
        let keep_local = self.paths[self.active].local_addr;
        let keep_peer = self.paths[self.active].peer_addr;

        self.paths.retain(|p: &mut Path| {
            let is_active = p.local_addr == keep_local && p.peer_addr == keep_peer;
            is_active || (!p.is_failed() && (p.is_validating() || !p.is_idle(now, idle)))
        });

        self.active = self
            .paths
            .iter()
            .position(|p| p.local_addr == keep_local && p.peer_addr == keep_peer)
            .unwrap_or(0);
    }

    pub fn next_timeout(&self) -> Option<Instant> {
        self.paths.iter().filter_map(Path::next_timeout).min()
    }

    fn best_validated(&self) -> Option<usize> {
        self.paths
            .iter()
            .enumerate()
            .filter(|(_, p)| p.is_validated())
            .max_by_key(|(_, p)| p.last_active())
            .map(|(i, _)| i)
    }

    fn find_evictable(&self) -> Option<usize> {
        self.paths
            .iter()
            .enumerate()
            .position(|(i, p)| i != self.active && !p.is_validating())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::time::Duration;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn challenge(n: u64) -> [u8; 8] {
        n.to_be_bytes()
    }

    #[test]
    fn path_validation_limited_mtu() {
        let client = addr("127.0.0.1:1234");
        let client2 = addr("127.0.0.1:5678");
        let server = addr("127.0.0.1:4321");
        let now = Instant::now();

        let mut paths = Paths::new(client, server, false, 2);
        let pid = paths.add_path(client2, server).unwrap();

        paths.get_mut(pid).unwrap().request_validation();
        assert!(paths.get(pid).unwrap().validation_requested());
        assert!(paths.get(pid).unwrap().probing_required());

        // PATH_CHALLENGE sent in a datagram with size: MIN_DATAGRAM - 1
        let data = challenge(1);
        paths
            .get_mut(pid)
            .unwrap()
            .add_challenge_sent(data, MIN_DATAGRAM - 1, now);

        assert!(!paths.get(pid).unwrap().validation_requested());
        assert!(!paths.get(pid).unwrap().probing_required());
        assert!(paths.get(pid).unwrap().is_validating());
        assert!(!paths.get(pid).unwrap().is_validated());
        assert_eq!(paths.get(pid).unwrap().state, PathState::Validating);

        // response: reachable, but MTU not validated yet
        assert_eq!(
            paths.on_path_response(data),
            Some((pid, ResponseOutcome::Reachable))
        );

        assert!(paths.get(pid).unwrap().validation_requested());
        assert!(paths.get(pid).unwrap().probing_required());
        assert!(paths.get(pid).unwrap().is_validating());
        assert!(!paths.get(pid).unwrap().is_validated());
        assert_eq!(paths.get(pid).unwrap().state, PathState::ValidatingMtu);
        assert!(paths.get(pid).unwrap().needs_mtu_validation());

        let data = challenge(2);
        paths
            .get_mut(pid)
            .unwrap()
            .add_challenge_sent(data, MIN_DATAGRAM, now);

        assert_eq!(
            paths.on_path_response(data),
            Some((pid, ResponseOutcome::Validated))
        );

        assert!(!paths.get(pid).unwrap().validation_requested());
        assert!(!paths.get(pid).unwrap().probing_required());
        assert!(!paths.get(pid).unwrap().is_validating());
        assert!(paths.get(pid).unwrap().is_validated());
        assert_eq!(paths.get(pid).unwrap().state, PathState::Validated);
    }

    #[test]
    fn multiple_probes() {
        let client = addr("127.0.0.1:1234");
        let server = addr("127.0.0.1:4321");
        let now = Instant::now();

        let mut paths = Paths::new(client, server, false, 2);
        let pid = paths.index_of(client, server).unwrap();
        let mut server_path = Path::new(server, client);

        // first probe
        let data = challenge(1);
        paths
            .get_mut(pid)
            .unwrap()
            .add_challenge_sent(data, MIN_DATAGRAM, now);

        // second probe
        let data_2 = challenge(2);
        paths
            .get_mut(pid)
            .unwrap()
            .add_challenge_sent(data_2, MIN_DATAGRAM, now);
        assert_eq!(paths.get(pid).unwrap().in_flight_challenges.len(), 2);

        // if we receive multiple challenges, we can store them
        server_path.on_path_challenge(data);
        assert_eq!(server_path.received_challenges.len(), 1);
        server_path.on_path_challenge(data_2);
        assert_eq!(server_path.received_challenges.len(), 2);

        // response for first probe
        assert!(paths.on_path_response(data).is_some());
        assert_eq!(paths.get(pid).unwrap().in_flight_challenges.len(), 1);

        // response for second probe
        assert!(paths.on_path_response(data_2).is_some());
        assert_eq!(paths.get(pid).unwrap().in_flight_challenges.len(), 0);
    }

    #[test]
    fn too_many_probes() {
        let client = addr("127.0.0.1:1234");
        let server = addr("127.0.0.1:4321");
        let now = Instant::now();

        let mut paths = Paths::new(client, server, false, 2);
        let pid = paths.index_of(client, server).unwrap();
        let mut server_path = Path::new(server, client);

        let datas: Vec<[u8; 8]> = (1u64..=4).map(challenge).collect();

        // sender tracks every challenge in flight
        for (n, d) in datas.iter().enumerate() {
            paths
                .get_mut(pid)
                .unwrap()
                .add_challenge_sent(*d, MIN_DATAGRAM, now);
            assert_eq!(paths.get(pid).unwrap().in_flight_challenges.len(), n + 1);
        }

        // receiver stores challenges only up to its queue size (MAX_RECV_CHALLENGES)
        for (n, d) in datas.iter().enumerate() {
            server_path.on_path_challenge(*d);
            assert_eq!(
                server_path.received_challenges.len(),
                (n + 1).min(MAX_RECV_CHALLENGES)
            );
        }

        // responses clean up in-flight challenges one by one. The fourth is
        // never answered, so one remains
        for (i, d) in datas.iter().take(3).enumerate() {
            assert!(paths.on_path_response(*d).is_some());
            assert_eq!(paths.get(pid).unwrap().in_flight_challenges.len(), 4 - (i + 1));
        }
        assert_eq!(paths.get(pid).unwrap().in_flight_challenges.len(), 1);
    }

    #[test]
    fn anti_amplification_lifts_on_reachability() {
        let mut path = Path::new(addr("127.0.0.1:1"), addr("127.0.0.1:2"));
        let now = Instant::now();

        path.on_datagram_received(100, now);
        assert_eq!(path.send_budget(), 300);

        path.request_validation();
        let data = challenge(1);
        path.add_challenge_sent(data, MIN_DATAGRAM - 1, now);
        assert!(path.send_budget() <= 300);

        assert_eq!(path.on_response_received(data), ResponseOutcome::Reachable);
        assert_eq!(path.send_budget(), MIN_DATAGRAM);
        assert!(path.needs_mtu_validation());
    }

    #[test]
    fn validation_abandoned_on_timeout() {
        let mut path = Path::new(addr("127.0.0.1:1"), addr("127.0.0.1:2"));
        let now = Instant::now();

        path.request_validation();
        path.add_challenge_sent(challenge(1), MIN_DATAGRAM, now);
        assert!(path.is_validating());

        let deadline = path.validation_deadline.unwrap();
        assert!(!path.on_validation_timeout(deadline - Duration::from_millis(1)));
        assert!(path.is_validating());

        assert!(path.on_validation_timeout(deadline));
        assert!(path.is_failed());
        assert!(!path.is_validating());
        assert!(path.in_flight_challenges.is_empty());
    }

    #[test]
    fn response_routed_by_challenge_match() {
        let server = addr("127.0.0.1:9");
        let mut paths = Paths::new(addr("127.0.0.1:1"), server, false, 2);
        let pid = paths.add_path(addr("127.0.0.1:2"), server).unwrap();
        let now = Instant::now();

        let data = challenge(7);
        let p = paths.get_mut(pid).unwrap();
        p.request_validation();
        p.add_challenge_sent(data, MIN_DATAGRAM, now);

        assert_eq!(
            paths.on_path_response(data),
            Some((pid, ResponseOutcome::Validated))
        );
        assert!(paths.get(pid).unwrap().is_validated());

        // unknown payload matches nothing
        assert_eq!(paths.on_path_response(challenge(99)), None);
    }

    #[test]
    fn active_failure_migrates_or_signals_no_viable_path() {
        let server = addr("127.0.0.1:9");

        // no alternative -> NO_VIABLE_PATH
        let mut solo = Paths::new(addr("127.0.0.1:1"), server, false, 2);
        let now = Instant::now();
        solo.active_mut().request_validation();
        solo.active_mut().add_challenge_sent(challenge(1), MIN_DATAGRAM, now);
        let dl = solo.active().validation_deadline.unwrap();
        assert_eq!(solo.on_timeout(dl), PathEvent::NoViablePath);
        assert!(solo.active().is_failed());

        // validated alternative -> migrate to it
        let mut paths = Paths::new(addr("127.0.0.1:1"), server, false, 3);
        paths.active_mut().request_validation();
        paths.active_mut().add_challenge_sent(challenge(1), MIN_DATAGRAM, now);
        let pid2 = paths.add_path(addr("127.0.0.1:2"), server).unwrap();
        paths.get_mut(pid2).unwrap().mark_validated();
        let dl = paths.active().validation_deadline.unwrap();
        assert_eq!(paths.on_timeout(dl), PathEvent::Migrated(pid2));
        assert_eq!(paths.active_idx(), pid2);
    }
}
