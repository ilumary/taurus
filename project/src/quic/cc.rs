use crate::{
    packet::AckFrame,
    transport_parameters::AckDelayExponent,
};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
use tracing::{debug, error, trace, warn};

// packets declared lost only after this many in-order unacked packets follow them
const K_PACKET_THRESHOLD: u64 = 3;

const K_TIME_THRESHOLD_NUM: u32 = 9;
const K_TIME_THRESHOLD_DEN: u32 = 8;

// minimum timer granularity. prevents spinning on tiny timeouts
const K_GRANULARITY: Duration = Duration::from_millis(1);

// assumed RTT before any measurement is available
const K_INITIAL_RTT: Duration = Duration::from_millis(333);

// default max_ack_delay until we receive the peers transport params
const K_DEFAULT_MAX_ACK_DELAY: Duration = Duration::from_millis(25);

const K_PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

// TODO will need to find place for shared space to define space ids
const SPACE_ID_INITIAL: usize = 0x00;
const SPACE_ID_HANDSHAKE: usize = 0x01;
const SPACE_ID_DATA: usize = 0x02;

/// placeholder congestion algorithm with an effectively unlimited window
#[derive(Default)]
pub struct UnlimitedWindow;

impl CongestionAlgorithm for UnlimitedWindow {
    fn on_packet_sent(&mut self, _bytes: usize, _bif: usize, _now: Instant) {}
    fn on_packets_acked(&mut self, _bytes: usize, _bif: usize, _now: Instant) {}
    fn on_congestion_event(
        &mut self,
        _lost: usize,
        _sent_time: Instant,
        _bif: usize,
        _now: Instant,
    ) {}
    fn on_persistent_congestion(&mut self) {}
    fn congestion_window(&self) -> usize {
        4096
    }
}

/// congestion-control algorithm trait
///
/// all timestamps use [`std::time::Instant`]
pub trait CongestionAlgorithm {
    /// a packet containing specified bytes of payload was placed in flight
    fn on_packet_sent(&mut self, bytes: usize, bytes_in_flight: usize, now: Instant);

    /// one or more previously in-flight packets were acknowledged
    fn on_packets_acked(&mut self, bytes_acked: usize, bytes_in_flight: usize, now: Instant);

    /// a congestion event occurred (one or more packets declared lost, or an
    /// ECN CE mark was received)
    ///
    /// `sent_time` is the send-time of the most recently sent lost packet
    fn on_congestion_event(
        &mut self,
        bytes_lost: usize,
        sent_time: Instant,
        bytes_in_flight: usize,
        now: Instant,
    );

    /// persistent congestion: the path has been unresponsive for longer than
    /// the persistent-congestion threshold (rfc 9002 sec. 7.6). the algorithm
    /// MUST reduce `cwnd` to the minimum window (`2 * max_datagram_size`)
    fn on_persistent_congestion(&mut self);

    /// current congestion window in bytes
    fn congestion_window(&self) -> usize;
}

/// rtt estimatation per RFC 9002 sec. 5
#[derive(Clone, Debug)]
pub struct RttEstimator {
    first_sample: bool,
    pub min_rtt: Duration,
    pub smoothed_rtt: Duration,
    pub rttvar: Duration,
    pub latest_rtt: Duration,

    /// `max_ack_delay` transport param from peer
    pub max_ack_delay: Duration,
}

impl RttEstimator {
    fn new() -> Self {
        Self {
            first_sample: true,
            min_rtt: Duration::MAX,
            smoothed_rtt: K_INITIAL_RTT,
            rttvar: K_INITIAL_RTT / 2,
            latest_rtt: Duration::ZERO,
            max_ack_delay: K_DEFAULT_MAX_ACK_DELAY,
        }
    }

    /// make a new rtt measurement per rfc 9002 sec. 5.3
    ///
    /// `ack_delay` is already decoded (scaled by `2^ack_delay_exponent`)
    pub fn update(&mut self, latest_rtt: Duration, ack_delay: Duration, space: usize) {
        self.latest_rtt = latest_rtt;

        if self.first_sample {
            self.first_sample = false;
            self.min_rtt = latest_rtt;
            self.smoothed_rtt = latest_rtt;
            self.rttvar = latest_rtt / 2;
            trace!(latest_rtt_us = latest_rtt.as_micros(), "rtt: first sample");
            return;
        }

        self.min_rtt = self.min_rtt.min(latest_rtt);

        let effective_delay = if space == SPACE_ID_DATA {
            ack_delay.min(self.max_ack_delay)
        } else {
            Duration::ZERO
        };

        let adjusted_rtt = if latest_rtt >= self.min_rtt + effective_delay {
            latest_rtt - effective_delay
        } else {
            latest_rtt
        };

        // rttvar = 3/4 · rttvar + 1/4 · |smoothed_rtt − adjusted_rtt|
        // smoothed_rtt = 7/8 · smoothed_rtt + 1/8 · adjusted_rtt
        let abs_diff = self.smoothed_rtt.abs_diff(adjusted_rtt);
        self.rttvar = (self.rttvar * 3 + abs_diff) / 4;
        self.smoothed_rtt = (self.smoothed_rtt * 7 + adjusted_rtt) / 8;

        trace!(
            latest_rtt_us = latest_rtt.as_micros(),
            smoothed_rtt_us = self.smoothed_rtt.as_micros(),
            rttvar_us = self.rttvar.as_micros(),
            min_rtt_us = self.min_rtt.as_micros(),
            "rtt: updated estimates"
        );
    }

    /// probe timeout interval
    ///
    /// `include_max_ack_delay` should be `true` only for the data space
    pub fn pto(&self, include_max_ack_delay: bool) -> Duration {
        let base = self.smoothed_rtt + (self.rttvar * 4).max(K_GRANULARITY);
        if include_max_ack_delay {
            base + self.max_ack_delay
        } else {
            base
        }
    }

    /// time-threshold loss delay `max(9/8 · max(smoothed_rtt, latest_rtt), kGranularity)`
    pub fn loss_delay(&self) -> Duration {
        let max_rtt = self.smoothed_rtt.max(self.latest_rtt);
        (max_rtt / K_TIME_THRESHOLD_DEN * K_TIME_THRESHOLD_NUM).max(K_GRANULARITY)
    }
}

#[derive(Clone, Debug)]
struct SentPacket {
    time_sent: Instant,
    size: usize,
}

/// state for one of the three spaces
struct SpaceState {
    // the slow part of removing an entry inside the queue is that is has to be reordered. by adding
    // the option we dont fully remove the object but replace it with a tombstone None value. that
    // allows us to only pop and push, making this very fast and highly scalable.
    sent: VecDeque<Option<SentPacket>>,

    // The packet number corresponding to sent[0]
    first_pn: u64,

    // largest acked packet number
    largest_acked: Option<u64>,

    //
    loss_time: Option<Instant>,

    // the time the latest packet was sent
    latest_sent: Option<Instant>,

    // current number of bytes in flight. effectively only needed here for initial and handshake
    // space so we can substract it from the overall once the handshake finished
    // TODO find out if we even need this
    bytes_in_flight: usize,
}

impl SpaceState {
    fn new() -> Self {
        Self {
            sent: VecDeque::new(),
            first_pn: 0,
            largest_acked: None,
            loss_time: None,
            latest_sent: None,
            bytes_in_flight: 0,
        }
    }

    /// call when a packet is proactively sent
    /// TODO replace with call into cc
    fn insert(&mut self, pn: u64, packet: SentPacket) {
        if self.sent.is_empty() {
            self.first_pn = pn;
        }

        let idx = (pn - self.first_pn) as usize;

        if self.sent.len() != idx {
            error!(
                first_pn = self.first_pn,
                sent_len = self.sent.len(),
                idx = idx,
                "mismatch between inserted pn and sent deque length"
            );
            return;
        }

        self.bytes_in_flight += packet.size;
        self.latest_sent = Some(packet.time_sent);
        self.sent.push_back(Some(packet));
    }

    fn get(&self, pn: u64) -> Option<&SentPacket> {
        if pn < self.first_pn {
            return None;
        }
        let idx = (pn - self.first_pn) as usize;
        self.sent.get(idx)?.as_ref()
    }

    fn remove_range(&mut self, start: u64, end: u64) -> Vec<(u64, SentPacket)> {
        let mut removed = Vec::new();

        let effective_start = start.max(self.first_pn);
        let start_idx = (effective_start - self.first_pn) as usize;
        let end_idx =
            (end.saturating_sub(self.first_pn) as usize).min(self.sent.len().saturating_sub(1));

        if start_idx >= self.sent.len() || start_idx > end_idx {
            return removed;
        }

        for idx in start_idx..=end_idx {
            if let Some(pkt) = self.sent[idx].take() {
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(pkt.size);
                removed.push((self.first_pn + idx as u64, pkt));
            }
        }

        // TODO investigate some kind of bulk remove
        while let Some(None) = self.sent.front() {
            self.sent.pop_front();
            self.first_pn += 1;
        }

        removed
    }

    fn detect_lost_packets(&mut self, loss_delay: Duration, now: Instant) -> (Vec<u64>, usize) {
        let Some(largest_acked) = self.largest_acked else {
            return (Vec::new(), 0);
        };

        let lost_send_time = now.checked_sub(loss_delay).unwrap_or(now);
        let mut lost_pns = Vec::new();
        let mut lost_bytes: usize = 0;
        self.loss_time = None;

        // basically limit search space for lost packets
        // packet-threshold bulk region is only valid when largest_acked >= K_PACKET_THRESHOLD
        // when it is not, bulk_limit = 0 and this loop is skipped entirely, but the time-threshold pass below still runs
        let bulk_limit = if largest_acked >= K_PACKET_THRESHOLD {
            let max_loss_pn  = largest_acked - K_PACKET_THRESHOLD;
            let max_loss_idx = max_loss_pn.saturating_sub(self.first_pn) as usize;
            (max_loss_idx + 1).min(self.sent.len())
        } else {
            0
        };

        // up until the limit, everything is lost
        for idx in 0..bulk_limit {
            if let Some(pkt) = self.sent[idx].take() {
                lost_bytes += pkt.size;
                lost_pns.push(self.first_pn + idx as u64);
            }
        }

        let acked_idx = (largest_acked.saturating_sub(self.first_pn)) as usize;
        let time_limit = acked_idx.min(self.sent.len());

        // between the limit and the most recent packet, it may only be considered lost due to time
        for idx in bulk_limit..time_limit {
            if let Some(pkt) = &self.sent[idx] {
                if pkt.time_sent <= lost_send_time {
                    let pkt = self.sent[idx].take().unwrap();
                    lost_bytes += pkt.size;
                    lost_pns.push(self.first_pn + idx as u64);
                } else {
                    let fires_at = pkt.time_sent + loss_delay;
                    self.loss_time = Some(self.loss_time.map_or(fires_at, |p| p.min(fires_at)));
                    break;
                }
            }
        }

        while let Some(None) = self.sent.front() {
            self.sent.pop_front();
            self.first_pn += 1;
        }

        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        (lost_pns, lost_bytes)
    }

    fn latest_sent(&self) -> Option<Instant> {
        self.latest_sent
    }
}

pub struct CongestionController<C: CongestionAlgorithm> {
    spaces: [SpaceState; 3],
    rtt: RttEstimator,

    bytes_in_flight: usize,

    ack_delay_exponent: u32,
    pto_count: u32,

    probe_pending: bool,

    handshake_confirmed: bool,
    algorithm: C,
}

impl<C: CongestionAlgorithm + Default> CongestionController<C> {
    pub fn with_default() -> Self {
        Self::new(C::default())
    }
}

impl<C: CongestionAlgorithm> CongestionController<C> {
    pub fn new(algorithm: C) -> Self {
        Self {
            spaces: [SpaceState::new(), SpaceState::new(), SpaceState::new()],
            rtt: RttEstimator::new(),
            bytes_in_flight: 0,
            ack_delay_exponent: 3,
            pto_count: 0,
            probe_pending: false,
            handshake_confirmed: false,
            algorithm,
        }
    }

    pub fn set_ack_delay_exponent(&mut self, ade: AckDelayExponent) {
        self.ack_delay_exponent = ade.get().get() as u32;
    }

    pub fn set_max_ack_delay(&mut self, delay: Duration) {
        self.rtt.max_ack_delay = delay;
    }

    // TODO maybe we still need to reset pto
    pub fn confirm_handshake(&mut self) {
        self.handshake_confirmed = true;

        self.bytes_in_flight = self
            .bytes_in_flight
            .saturating_sub(self.spaces[SPACE_ID_INITIAL].bytes_in_flight);
        self.spaces[SPACE_ID_INITIAL] = SpaceState::new();
        self.bytes_in_flight = self
            .bytes_in_flight
            .saturating_sub(self.spaces[SPACE_ID_HANDSHAKE].bytes_in_flight);
        self.spaces[SPACE_ID_HANDSHAKE] = SpaceState::new();
    }

    /// packet must be ack-eliciting. there is an edge case because padding frames count towards
    /// in-flight yet are not ack-eliciting. such a frame may be sent as a probe. the solution is
    /// to use a PING frame as probe which is ack-eliciting, eliminating the edge case.
    pub fn on_packet_sent(&mut self, space: usize, pn: u64, size: usize, now: Instant) {
        self.bytes_in_flight += size;
        self.probe_pending = false;

        self.spaces[space].insert(
            pn,
            SentPacket {
                time_sent: now,
                size,
            },
        );
        self.algorithm
            .on_packet_sent(size, self.bytes_in_flight, now);

        trace!(
            ?space,
            pn,
            size,
            bytes_in_flight = self.bytes_in_flight(),
            "packet sent"
        );
    }

    /// available congestion window for sending
    pub fn available_window(&self) -> usize {
        self.algorithm
            .congestion_window()
            .saturating_sub(self.bytes_in_flight)
    }

    /// process a received ack frame
    ///
    /// returns `(acked_pns, lost_pns)`
    #[tracing::instrument(
        name = "cc::on_ack_received",
        skip_all,
        fields(space = ?space, largest_acked = ack_frame.largest_acknowledged())
    )]
    pub fn on_ack_received(
        &mut self,
        space: usize,
        ack_frame: &AckFrame,
        now: Instant,
    ) -> (Vec<u64>, Vec<u64>) {
        let largest_acked = ack_frame.largest_acknowledged();

        let is_new_largest = self.spaces[space]
            .largest_acked
            .is_none_or(|prev| largest_acked > prev);

        if is_new_largest {
            if let Some(time_sent) = self.spaces[space].get(largest_acked).map(|p| p.time_sent) {
                let latest_rtt = now.duration_since(time_sent);
                let ack_delay = self.decode_ack_delay(ack_frame.ack_delay());
                self.rtt.update(latest_rtt, ack_delay, space);
            }
            self.spaces[space].largest_acked = Some(largest_acked);
        }

        let mut acked_pns: Vec<u64> = Vec::new();
        let mut acked_bytes: usize = 0;

        for ri in ack_frame.ranges() {
            for (pn, pkt) in self.spaces[space].remove_range(*ri.start(), *ri.end()) {
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(pkt.size);
                acked_bytes += pkt.size;
                acked_pns.push(pn);
            }
        }

        if !acked_pns.is_empty() {
            debug!(
                count = acked_pns.len(),
                bytes = acked_bytes,
                bytes_in_flight = self.bytes_in_flight(),
                "packets acknowledged"
            );
            self.algorithm
                .on_packets_acked(acked_bytes, self.bytes_in_flight, now);
            self.pto_count = 0;
        }

        let loss_delay = self.rtt.loss_delay();
        let (lost_pns, lost_bytes) = self.spaces[space].detect_lost_packets(loss_delay, now);

        if !lost_pns.is_empty() {
            debug!(
                count = lost_pns.len(),
                bytes = lost_bytes,
                bytes_in_flight = self.bytes_in_flight(),
                "packets declared lost"
            );
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
            self.algorithm
                .on_congestion_event(lost_bytes, now, self.bytes_in_flight, now);
        }

        (acked_pns, lost_pns)
    }

    /// the deadline by which the loss detection timer must fire, or `None`
    /// when no timer is needed
    pub fn loss_detection_timeout(&self) -> Option<Instant> {
        let earliest_loss_time = (SPACE_ID_INITIAL..=SPACE_ID_DATA)
            .filter_map(|s| self.spaces[s].loss_time)
            .min();

        if let Some(t) = earliest_loss_time {
            return Some(t);
        }

        let any_in_flight = (SPACE_ID_INITIAL..=SPACE_ID_DATA)
            .any(|s| self.spaces[s].bytes_in_flight > 0);

        if !any_in_flight && self.handshake_confirmed {
            return None;
        }

        let latest_sent = (SPACE_ID_INITIAL..=SPACE_ID_DATA)
            .filter_map(|s| self.spaces[s].latest_sent())
            .max()?;

        let pto = self.rtt.pto(self.handshake_confirmed);
        let backoff = 1u32.checked_shl(self.pto_count.min(30)).unwrap_or(u32::MAX);
        Some(latest_sent + pto * backoff)
    }

    /// returns lost pns. empty vec = PTO probe required
    #[tracing::instrument(name = "cc::on_loss_detection_timeout", skip_all)]
    pub fn on_loss_detection_timeout(&mut self, now: Instant) -> Vec<u64> {
        let has_loss_time = self.spaces[SPACE_ID_INITIAL].loss_time.is_some()
            || self.spaces[SPACE_ID_HANDSHAKE].loss_time.is_some()
            || self.spaces[SPACE_ID_DATA].loss_time.is_some();

        if has_loss_time {
            let loss_delay = self.rtt.loss_delay();
            let mut all_lost = Vec::new();
            let mut total_bytes: usize = 0;
            for space in SPACE_ID_INITIAL..=SPACE_ID_DATA {
                let (pns, bytes) = self.spaces[space].detect_lost_packets(loss_delay, now);
                total_bytes += bytes;
                all_lost.extend(pns);
            }
            if !all_lost.is_empty() {
                warn!(
                    count = all_lost.len(),
                    bytes = total_bytes,
                    bytes_in_flight = self.bytes_in_flight(),
                    "loss detection timeout: packets declared lost"
                );
                self.algorithm
                    .on_congestion_event(total_bytes, now, self.bytes_in_flight(), now);
            }
            return all_lost; // non-empty = lost
        }

        self.pto_count += 1;
        self.probe_pending = true;

        debug!(
            pto_count = self.pto_count,
            bytes_in_flight = self.bytes_in_flight(),
            "loss detection timeout: probe required"
        );

        Vec::new() // empty = probe required
    }

    #[inline]
    pub fn probe_pending(&self) -> bool {
        self.probe_pending
    }

    #[inline]
    pub fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }

    /// don't confuse with `available_window`
    pub fn congestion_window(&self) -> usize {
        self.algorithm.congestion_window()
    }

    pub fn rtt(&self) -> &RttEstimator {
        &self.rtt
    }

    pub fn pto_count(&self) -> u32 {
        self.pto_count
    }

    pub fn pto(&self) -> Duration {
        self.rtt.pto(self.handshake_confirmed)
    }

    fn decode_ack_delay(&self, encoded: u64) -> Duration {
        Duration::from_micros(encoded.saturating_mul(1u64 << self.ack_delay_exponent))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_first_sample_initialises_all_fields() {
        let mut rtt = RttEstimator::new();
        rtt.update(Duration::from_millis(100), Duration::ZERO, SPACE_ID_DATA);
        assert_eq!(rtt.latest_rtt, Duration::from_millis(100));
        assert_eq!(rtt.smoothed_rtt, Duration::from_millis(100));
        assert_eq!(rtt.rttvar, Duration::from_millis(50));
        assert_eq!(rtt.min_rtt, Duration::from_millis(100));
    }

    #[test]
    fn rtt_ewma_second_sample() {
        let mut rtt = RttEstimator::new();
        rtt.update(Duration::from_millis(100), Duration::ZERO, SPACE_ID_DATA);
        rtt.update(Duration::from_millis(200), Duration::ZERO, SPACE_ID_DATA);
        let expected = (Duration::from_millis(100) * 7 + Duration::from_millis(200)) / 8;
        assert_eq!(rtt.smoothed_rtt, expected);
    }

    #[test]
    fn rtt_ack_delay_applied_in_data_space() {
        let mut rtt = RttEstimator::new();
        rtt.update(Duration::from_millis(100), Duration::ZERO, SPACE_ID_DATA);
        rtt.update(
            Duration::from_millis(150),
            Duration::from_millis(20),
            SPACE_ID_DATA,
        );
        let expected = (Duration::from_millis(100) * 7 + Duration::from_millis(130)) / 8;
        assert_eq!(rtt.smoothed_rtt, expected);
    }

    #[test]
    fn rtt_ack_delay_ignored_outside_data_space() {
        let mut rtt = RttEstimator::new();
        rtt.update(Duration::from_millis(100), Duration::ZERO, SPACE_ID_INITIAL);
        rtt.update(
            Duration::from_millis(150),
            Duration::from_millis(20),
            SPACE_ID_INITIAL,
        );
        let expected = (Duration::from_millis(100) * 7 + Duration::from_millis(150)) / 8;
        assert_eq!(rtt.smoothed_rtt, expected);
    }

    #[test]
    fn rtt_ack_delay_capped_at_max_ack_delay() {
        let mut rtt = RttEstimator::new();
        rtt.max_ack_delay = Duration::from_millis(25);
        rtt.update(Duration::from_millis(100), Duration::ZERO, SPACE_ID_DATA);
        rtt.update(
            Duration::from_millis(200),
            Duration::from_millis(50),
            SPACE_ID_DATA,
        );
        let expected = (Duration::from_millis(100) * 7 + Duration::from_millis(175)) / 8;
        assert_eq!(rtt.smoothed_rtt, expected);
    }

    #[test]
    fn rtt_ack_delay_not_applied_when_result_below_min_rtt() {
        let mut rtt = RttEstimator::new();
        rtt.update(Duration::from_millis(100), Duration::ZERO, SPACE_ID_DATA);
        rtt.update(
            Duration::from_millis(110),
            Duration::from_millis(20),
            SPACE_ID_DATA,
        );
        let expected = (Duration::from_millis(100) * 7 + Duration::from_millis(110)) / 8;
        assert_eq!(rtt.smoothed_rtt, expected);
    }

    #[test]
    fn rtt_min_rtt_tracks_minimum() {
        let mut rtt = RttEstimator::new();
        for ms in [200, 50, 300] {
            rtt.update(Duration::from_millis(ms), Duration::ZERO, SPACE_ID_DATA);
        }
        assert_eq!(rtt.min_rtt, Duration::from_millis(50));
    }

    #[test]
    fn rtt_pto_difference_equals_max_ack_delay() {
        let mut rtt = RttEstimator::new();
        rtt.update(Duration::from_millis(100), Duration::ZERO, SPACE_ID_DATA);
        rtt.max_ack_delay = Duration::from_millis(25);
        assert_eq!(rtt.pto(true) - rtt.pto(false), Duration::from_millis(25));
    }

    // --- SpaceState

    fn pkt(time_sent: Instant) -> SentPacket {
        SentPacket {
            time_sent,
            size: 100,
        }
    }

    fn pkt_sized(time_sent: Instant, size: usize) -> SentPacket {
        SentPacket { time_sent, size }
    }

    fn insert_sequential(s: &mut SpaceState, base_pn: u64, count: u64, t0: Instant) {
        for i in 0..count {
            s.insert(base_pn + i, pkt(t0 + Duration::from_millis(i * 10)));
        }
    }

    #[test]
    fn space_state_insert_sequential_no_loss() {
        let mut s = SpaceState::new();
        let t0 = Instant::now();
        insert_sequential(&mut s, 0, 15, t0);

        assert_eq!(s.first_pn, 0);
        assert_eq!(s.sent.len(), 15);
        assert_eq!(s.bytes_in_flight, 15 * 100);
        assert_eq!(s.latest_sent, Some(t0 + Duration::from_millis(140)));
        assert!(s.largest_acked.is_none());
        assert!(s.loss_time.is_none());

        for i in 0u64..15 {
            assert!(s.get(i).is_some(), "pn {i} should be present");
        }

        let (lost, bytes) =
            s.detect_lost_packets(Duration::from_millis(200), t0 + Duration::from_millis(500));
        assert!(lost.is_empty());
        assert_eq!(bytes, 0);
    }

    #[test]
    fn space_state_remove_range_from_front() {
        let mut s = SpaceState::new();
        let t0 = Instant::now();
        insert_sequential(&mut s, 0, 15, t0);

        let removed = s.remove_range(0, 4);

        assert_eq!(removed.len(), 5);

        let mut pns: Vec<u64> = removed.iter().map(|(pn, _)| *pn).collect();
        pns.sort_unstable();
        assert_eq!(pns, vec![0, 1, 2, 3, 4]);

        assert_eq!(s.first_pn, 5);
        assert_eq!(s.sent.len(), 10);
        assert_eq!(s.bytes_in_flight, 10 * 100);

        for i in 5u64..15 {
            assert!(s.get(i).is_some(), "pn {i} should still be present");
        }

        for i in 0u64..5 {
            assert!(s.get(i).is_none(), "pn {i} should be gone");
        }
    }

    #[test]
    fn space_state_remove_range_middle_leaves_tombstones() {
        let mut s = SpaceState::new();
        let t0 = Instant::now();
        insert_sequential(&mut s, 0, 10, t0);

        let removed = s.remove_range(3, 6);
        assert_eq!(removed.len(), 4);

        assert_eq!(s.first_pn, 0);
        assert_eq!(s.sent.len(), 10);
        assert_eq!(s.bytes_in_flight, 6 * 100);

        for i in [0u64, 1, 2, 7, 8, 9] {
            assert!(s.get(i).is_some(), "pn {i} should be present");
        }

        for i in 3u64..=6 {
            assert!(s.get(i).is_none(), "pn {i} should be a tombstone");
        }
    }

    #[test]
    fn space_state_tombstones_drain_when_front_is_cleared() {
        let mut s = SpaceState::new();
        let t0 = Instant::now();
        insert_sequential(&mut s, 0, 5, t0);

        s.remove_range(1, 3);
        assert_eq!(s.first_pn, 0);
        assert_eq!(s.sent.len(), 5);

        s.remove_range(0, 0);
        assert_eq!(
            s.first_pn, 4,
            "first_pn should skip over drained tombstones"
        );
        assert_eq!(s.sent.len(), 1);
        assert_eq!(s.bytes_in_flight, 100);
    }

    #[test]
    fn space_state_packet_threshold_loss() {
        let mut s = SpaceState::new();
        let t0 = Instant::now();
        insert_sequential(&mut s, 0, 10, t0);

        s.largest_acked = Some(9);

        let (lost, bytes) =
            s.detect_lost_packets(Duration::from_secs(100), t0 + Duration::from_millis(200));

        let mut lost_sorted = lost.clone();
        lost_sorted.sort_unstable();
        assert_eq!(lost_sorted, vec![0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(bytes, 7 * 100);
        assert_eq!(s.bytes_in_flight, 3 * 100);

        assert_eq!(s.first_pn, 7);
    }

    #[test]
    fn space_state_packet_threshold_exact_boundary() {
        let mut s = SpaceState::new();
        let t0 = Instant::now();
        insert_sequential(&mut s, 0, 5, t0);
        s.largest_acked = Some(4);

        let (lost, _) =
            s.detect_lost_packets(Duration::from_secs(100), t0 + Duration::from_millis(200));

        let mut lost_sorted = lost;
        lost_sorted.sort_unstable();
        assert_eq!(lost_sorted, vec![0, 1]);
        assert!(s.get(2).is_some(), "pn 2 must survive");
        assert!(s.get(3).is_some(), "pn 3 must survive");
    }

    #[test]
    fn space_state_time_threshold_loss() {
        let mut s = SpaceState::new();
        let t0 = Instant::now();

        for i in 0u64..5 {
            s.insert(i, pkt(t0));
        }
        s.largest_acked = Some(4);

        let (lost, bytes) =
            s.detect_lost_packets(Duration::from_millis(50), t0 + Duration::from_millis(100));

        let mut lost_sorted = lost;
        lost_sorted.sort_unstable();
        assert_eq!(lost_sorted, vec![0, 1, 2, 3]);
        assert_eq!(bytes, 4 * 100);
    }

    #[test]
    fn space_state_loss_time_set_for_pending_packet() {
        let mut s = SpaceState::new();
        let t0 = Instant::now();

        s.insert(0, pkt(t0));
        s.insert(1, pkt(t0 + Duration::from_millis(200)));
        s.insert(2, pkt(t0 + Duration::from_millis(400)));
        s.largest_acked = Some(2);

        let loss_delay = Duration::from_millis(100);
        let now = t0 + Duration::from_millis(120);
        let (lost, _) = s.detect_lost_packets(loss_delay, now);

        assert_eq!(lost, vec![0]);
        let expected_loss_time = t0 + Duration::from_millis(300);
        assert!(s.loss_time.is_some());
        assert_eq!(s.loss_time.unwrap(), expected_loss_time);
    }

    #[test]
    fn space_state_loss_time_resets_each_call() {
        let mut s = SpaceState::new();
        let t0 = Instant::now();

        s.insert(0, pkt(t0));
        s.insert(1, pkt(t0 + Duration::from_millis(200)));
        s.insert(2, pkt(t0 + Duration::from_millis(400)));
        s.largest_acked = Some(2);

        let loss_delay = Duration::from_millis(100);

        s.detect_lost_packets(loss_delay, t0 + Duration::from_millis(120));
        assert!(s.loss_time.is_some());

        s.detect_lost_packets(loss_delay, t0 + Duration::from_millis(400));
        assert!(s.loss_time.is_none(), "stale loss_time must be cleared");
    }

    #[test]
    fn space_state_tombstones_in_time_threshold_region() {
        let mut s = SpaceState::new();
        let t0 = Instant::now();

        insert_sequential(&mut s, 0, 8, t0);

        s.remove_range(2, 3);
        s.largest_acked = Some(7);

        let (lost, bytes) =
            s.detect_lost_packets(Duration::from_secs(100), t0 + Duration::from_millis(200));

        let mut lost_sorted = lost;
        lost_sorted.sort_unstable();
        assert_eq!(lost_sorted, vec![0, 1, 4]);
        assert_eq!(bytes, 3 * 100);
    }

    #[test]
    fn space_state_no_loss_beyond_largest_acked() {
        let mut s = SpaceState::new();
        let t0 = Instant::now();

        for i in 0u64..5 {
            s.insert(i, pkt(t0));
        }
        s.largest_acked = Some(3);

        let (lost, _) =
            s.detect_lost_packets(Duration::from_millis(1), t0 + Duration::from_millis(500));

        let lost_set: std::collections::HashSet<u64> = lost.into_iter().collect();
        assert!(
            !lost_set.contains(&4),
            "pn 4 is still in flight, must not be declared lost"
        );
    }

    #[test]
    fn space_state_bytes_in_flight_accounting() {
        let mut s = SpaceState::new();
        let t0 = Instant::now();

        s.insert(0, pkt_sized(t0, 200));
        s.insert(1, pkt_sized(t0 + Duration::from_millis(10), 300));
        s.insert(2, pkt_sized(t0 + Duration::from_millis(20), 150));
        s.insert(3, pkt_sized(t0 + Duration::from_millis(30), 400));
        assert_eq!(s.bytes_in_flight, 1050);

        s.remove_range(0, 1);
        assert_eq!(s.bytes_in_flight, 550);

        s.largest_acked = Some(3);
        let (_, lost_bytes) =
            s.detect_lost_packets(Duration::from_millis(1), t0 + Duration::from_millis(200));
        assert_eq!(lost_bytes, 150);
        assert_eq!(s.bytes_in_flight, 400);
    }

    #[test]
    fn space_state_double_remove_range_idempotent() {
        let mut s = SpaceState::new();
        let t0 = Instant::now();
        insert_sequential(&mut s, 0, 5, t0);

        let first = s.remove_range(1, 3);
        assert_eq!(first.len(), 3);

        let second = s.remove_range(1, 3);
        assert!(
            second.is_empty(),
            "re-removing already-removed range must return nothing"
        );
        assert_eq!(s.bytes_in_flight, 2 * 100);
    }

    #[test]
    fn space_state_remove_range_past_end_is_safe() {
        let mut s = SpaceState::new();
        let t0 = Instant::now();
        insert_sequential(&mut s, 0, 3, t0);

        let removed = s.remove_range(0, 99);
        assert_eq!(removed.len(), 3);
        assert_eq!(s.bytes_in_flight, 0);
        assert!(s.sent.is_empty());
    }

    #[test]
    fn space_state_fresh_insert_after_full_drain() {
        let mut s = SpaceState::new();
        let t0 = Instant::now();
        insert_sequential(&mut s, 0, 5, t0);

        s.remove_range(0, 4);
        assert!(s.sent.is_empty());
        assert_eq!(s.first_pn, 5);

        let t1 = t0 + Duration::from_millis(1000);
        insert_sequential(&mut s, 5, 3, t1);

        assert_eq!(s.first_pn, 5);
        assert_eq!(s.sent.len(), 3);
        assert_eq!(s.bytes_in_flight, 3 * 100);
        assert!(s.get(5).is_some());
        assert!(s.get(6).is_some());
        assert!(s.get(7).is_some());
    }

    #[test]
    fn space_state_get_out_of_bounds_is_none() {
        let mut s = SpaceState::new();
        let t0 = Instant::now();
        insert_sequential(&mut s, 10, 5, t0);

        assert!(s.get(9).is_none(), "pn before first_pn");
        assert!(s.get(15).is_none(), "pn beyond sent length");
        assert!(s.get(0).is_none(), "pn far below first_pn");
    }

    #[test]
    fn space_state_no_loss_without_largest_acked() {
        let mut s = SpaceState::new();
        let t0 = Instant::now();
        insert_sequential(&mut s, 0, 5, t0);

        let (lost, bytes) =
            s.detect_lost_packets(Duration::from_millis(1), t0 + Duration::from_millis(9999));
        assert!(lost.is_empty());
        assert_eq!(bytes, 0);
        assert_eq!(s.bytes_in_flight, 5 * 100, "bif must be unchanged");
    }

    #[test]
    fn space_state_largest_acked_below_threshold() {
        let mut s = SpaceState::new();
        let t0 = Instant::now();
        insert_sequential(&mut s, 0, 3, t0);
        s.largest_acked = Some(1);

        let (lost, bytes) =
            s.detect_lost_packets(Duration::from_secs(100), t0 + Duration::from_millis(50));
        assert!(lost.is_empty());
        assert_eq!(bytes, 0);
    }
}
