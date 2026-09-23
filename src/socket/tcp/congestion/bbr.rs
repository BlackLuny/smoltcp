use crate::time::{Duration, Instant};

use super::{Controller, RttEstimator};

mod bw_estimation;
mod min_max;

use bw_estimation::BandwidthEstimation;

/// Experimental BBR congestion control algorithm.
///
/// Aims for reduced buffer bloat and improved performance over high bandwidth-delay product networks.
/// Based on google's quiche implementation <https://source.chromium.org/chromium/chromium/src/+/master:net/third_party/quiche/src/quic/core/congestion_control/bbr_sender.cc>
/// of BBR <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control>.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Bbr {
    max_bandwidth: BandwidthEstimation,
    acked_bytes: u64,
    mode: Mode,
    loss_state: LossState,
    recovery_state: RecoveryState,
    recovery_window: usize,
    is_at_full_bandwidth: bool,
    pacing_gain: f32,
    high_gain: f32,
    drain_gain: f32,
    cwnd_gain: f32,
    high_cwnd_gain: f32,
    last_cycle_start: Option<Instant>,
    current_cycle_offset: u8,
    init_cwnd: usize,
    min_cwnd: usize,
    prev_in_flight_count: usize,
    /// NOTE(zfc): bytes in flight after the ACK being processed, as reported by the
    /// socket. The original port approximated in-flight with `cwnd` everywhere; with
    /// cwnd actually enforced (#637) that approximation can never drop below the
    /// ProbeRTT target, so ProbeRTT never exits and BtlBw decays to the floor.
    bytes_in_flight: usize,
    exit_probe_rtt_at: Option<Instant>,
    probe_rtt_last_started_at: Option<Instant>,
    min_rtt: Duration,
    // Idle restart flag: set when restarting after idle period
    // This matches Linux BBR (tcp_bbr.c:101)
    idle_restart: bool,
    max_acked_packet_number: u64,
    max_sent_packet_number: u64,
    end_recovery_at_packet_number: u64,
    cwnd: usize,
    current_round_trip_end_packet_number: u64,
    round_count: u64,
    bw_at_last_round: u64,
    round_wo_bw_gain: u64,
    ack_aggregation: AckAggregationState,
    rwnd: usize,
    // Simple linear congruential generator for randomness (no_std compatible)
    rng_state: u32,
    // App-limited tracking: true when the application doesn't have enough data to fill cwnd
    app_limited: bool,
    // Prior cwnd before loss recovery (for restoration after recovery exits)
    prior_cwnd: usize,
    // Packet conservation flag: follow packet conservation principle during first round of recovery
    // This matches Linux BBR (tcp_bbr.c:99)
    packet_conservation: bool,
    // Previous congestion avoidance state for tracking recovery entry/exit
    // This matches Linux BBR (tcp_bbr.c:98) but simplified to bool (in_recovery)
    prev_in_recovery: bool,
    // Round start flag: indicates if we've started a new round trip
    // This matches Linux BBR (tcp_bbr.c:100)
    round_start: bool,
}

impl Bbr {
    pub fn new() -> Self {
        let initial_window = 1024 * 10;
        let min_window = 1024 * 2;
        Self {
            max_bandwidth: BandwidthEstimation::default(),
            acked_bytes: 0,
            mode: Mode::Startup,
            loss_state: Default::default(),
            recovery_state: RecoveryState::NotInRecovery,
            recovery_window: 0,
            is_at_full_bandwidth: false,
            pacing_gain: K_DEFAULT_HIGH_GAIN,
            high_gain: K_DEFAULT_HIGH_GAIN,
            drain_gain: 1.0 / K_DEFAULT_HIGH_GAIN,
            cwnd_gain: K_DEFAULT_HIGH_GAIN,
            high_cwnd_gain: K_DEFAULT_HIGH_GAIN,
            last_cycle_start: None,
            current_cycle_offset: 0,
            init_cwnd: initial_window,
            min_cwnd: min_window,
            prev_in_flight_count: 0,
            bytes_in_flight: 0,
            exit_probe_rtt_at: None,
            probe_rtt_last_started_at: None,
            min_rtt: Duration::ZERO,
            idle_restart: false,
            max_acked_packet_number: 0,
            max_sent_packet_number: 0,
            end_recovery_at_packet_number: 0,
            cwnd: initial_window,
            current_round_trip_end_packet_number: 0,
            round_count: 0,
            bw_at_last_round: 0,
            round_wo_bw_gain: 0,
            ack_aggregation: AckAggregationState {
                extra_acked: [0, 0],
                extra_acked_win_idx: 0,
                extra_acked_win_rtts: 0,
                ack_epoch_mstamp: None,
                ack_epoch_acked: 0,
            },
            rwnd: 64 * 1024,
            rng_state: 12345, // Arbitrary seed
            app_limited: false,
            prior_cwnd: initial_window,
            packet_conservation: false,
            prev_in_recovery: false,
            round_start: false,
        }
    }

    // Simple pseudo-random number generator (LCG)
    fn random_range(&mut self, max: u8) -> u8 {
        self.rng_state = self.rng_state.wrapping_mul(1103515245).wrapping_add(12345);
        ((self.rng_state / 65536) % max as u32) as u8
    }

    fn enter_startup_mode(&mut self) {
        self.mode = Mode::Startup;
        self.pacing_gain = self.high_gain;
        self.cwnd_gain = self.high_cwnd_gain;
    }

    fn enter_probe_bandwidth_mode(&mut self, now: Instant) {
        self.mode = Mode::ProbeBw;
        self.cwnd_gain = K_DERIVED_HIGH_CWNDGAIN;
        self.last_cycle_start = Some(now);
        // Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
        // excluded because in that case increased gain and decreased gain would not
        // follow each other.
        let mut rand_index = self.random_range((K_PACING_GAIN.len() as u8) - 1);
        if rand_index >= 1 {
            rand_index += 1;
        }
        self.current_cycle_offset = rand_index;
        self.pacing_gain = K_PACING_GAIN[rand_index as usize];
    }

    fn save_cwnd(&mut self) {
        // Save current cwnd before entering recovery
        // This matches Linux BBR (tcp_bbr.c:756, 884)
        if self.recovery_state == RecoveryState::NotInRecovery && self.mode != Mode::ProbeRtt {
            self.prior_cwnd = self.cwnd;
        }
    }

    fn restore_cwnd(&mut self) {
        // Restore cwnd when exiting recovery
        // This matches Linux BBR (tcp_bbr.c:785, 903)
        self.cwnd = self.cwnd.max(self.prior_cwnd);
    }

    /// Packet conservation: handle recovery and restoration of cwnd.
    /// Matches Linux BBR bbr_set_cwnd_to_recover_or_restore() (tcp_bbr.c:480-514)
    ///
    /// On the first round of recovery, follow packet conservation principle:
    /// send P packets per P packets acked. After that, slow-start and send
    /// at most 2*P packets per P packets acked.
    fn set_cwnd_to_recover_or_restore(
        &mut self,
        bytes_acked: usize,
        bytes_lost: usize,
        bytes_in_flight: usize,
    ) -> Option<usize> {
        let in_recovery = self.recovery_state.in_recovery();
        let mut cwnd = self.cwnd;

        // An ACK for P pkts should release at most 2*P packets. We do this
        // in two steps. First, here we deduct the number of lost packets.
        // Then, in calculate_cwnd() we slow start up toward the target cwnd.
        // Matches tcp_bbr.c:492-493
        if bytes_lost > 0 {
            cwnd = cwnd.saturating_sub(bytes_lost).max(MAX_SEGMENT_SIZE);
        }

        // Entering recovery: start packet conservation
        // Matches tcp_bbr.c:495-500
        if in_recovery && !self.prev_in_recovery {
            // Starting 1st round of Recovery, so do packet conservation.
            self.packet_conservation = true;
            // Start new round now
            self.current_round_trip_end_packet_number = self.round_end_mark();
            // Cut unused cwnd from app behavior or other factors
            cwnd = bytes_in_flight.saturating_add(bytes_acked);
        }
        // Exiting recovery: restore cwnd
        // Matches tcp_bbr.c:501-504
        else if !in_recovery && self.prev_in_recovery {
            // Exiting loss recovery; restore cwnd saved before recovery.
            cwnd = cwnd.max(self.prior_cwnd);
            self.packet_conservation = false;
        }

        // Update prev state for next time
        self.prev_in_recovery = in_recovery;

        // If using packet conservation, ensure cwnd >= inflight + acked
        // Matches tcp_bbr.c:508-513
        if self.packet_conservation {
            let conserved_cwnd = bytes_in_flight.saturating_add(bytes_acked).max(cwnd);
            Some(conserved_cwnd)
        } else {
            Some(cwnd)
        }
    }

    fn update_recovery_state(&mut self, is_round_start: bool) {
        // Exit recovery when there are no losses for a round.
        if self.loss_state.has_losses() {
            self.end_recovery_at_packet_number = self.round_end_mark();
        }
        match self.recovery_state {
            // Enter conservation on the first loss.
            RecoveryState::NotInRecovery if self.loss_state.has_losses() => {
                // Save cwnd before entering recovery (matches Linux BBR)
                self.save_cwnd();
                self.recovery_state = RecoveryState::Conservation;
                // This will cause the |recovery_window| to be set to the
                // correct value in calculate_recovery_window().
                self.recovery_window = 0;
                // Since the conservation phase is meant to be lasting for a whole
                // round, extend the current round as if it were started right now.
                self.current_round_trip_end_packet_number = self.round_end_mark();
            }
            RecoveryState::Growth | RecoveryState::Conservation => {
                if self.recovery_state == RecoveryState::Conservation && is_round_start {
                    self.recovery_state = RecoveryState::Growth;
                }
                // Exit recovery if appropriate.
                if !self.loss_state.has_losses()
                    && self.max_acked_packet_number > self.end_recovery_at_packet_number
                {
                    // Restore cwnd when exiting recovery (matches Linux BBR)
                    self.restore_cwnd();
                    self.recovery_state = RecoveryState::NotInRecovery;
                }
            }
            _ => {}
        }
    }

    fn update_gain_cycle_phase(&mut self, now: Instant, in_flight: usize) {
        // In most cases, the cycle is advanced after an RTT passes.
        let mut should_advance_gain_cycling = self
            .last_cycle_start
            .map(|last_cycle_start| {
                if now > last_cycle_start {
                    now - last_cycle_start > self.min_rtt
                } else {
                    false
                }
            })
            .unwrap_or(false);

        // If the pacing gain is above 1.0, the connection is trying to probe the
        // bandwidth by increasing the number of bytes in flight to at least
        // pacing_gain * BDP.  Make sure that it actually reaches the target, as
        // long as there are no losses suggesting that the buffers are not able to
        // hold that much.
        if self.pacing_gain > 1.0
            && !self.loss_state.has_losses()
            && self.prev_in_flight_count < self.get_target_cwnd(self.pacing_gain)
        {
            should_advance_gain_cycling = false;
        }

        // If pacing gain is below 1.0, the connection is trying to drain the extra
        // queue which could have been incurred by probing prior to it.  If the
        // number of bytes in flight falls down to the estimated BDP value earlier,
        // conclude that the queue has been successfully drained and exit this cycle
        // early.
        if self.pacing_gain < 1.0 && in_flight <= self.get_target_cwnd(1.0) {
            should_advance_gain_cycling = true;
        }

        if should_advance_gain_cycling {
            self.current_cycle_offset = (self.current_cycle_offset + 1) % K_PACING_GAIN.len() as u8;
            self.last_cycle_start = Some(now);
            // Stay in low gain mode until the target BDP is hit.  Low gain mode
            // will be exited immediately when the target BDP is achieved.
            if DRAIN_TO_TARGET
                && self.pacing_gain < 1.0
                && (K_PACING_GAIN[self.current_cycle_offset as usize] - 1.0).abs() < f32::EPSILON
                && in_flight > self.get_target_cwnd(1.0)
            {
                return;
            }
            self.pacing_gain = K_PACING_GAIN[self.current_cycle_offset as usize];
        }
    }

    fn maybe_exit_startup_or_drain(&mut self, now: Instant, in_flight: usize) {
        if self.mode == Mode::Startup && self.is_at_full_bandwidth {
            self.mode = Mode::Drain;
            self.pacing_gain = self.drain_gain;
            self.cwnd_gain = self.high_cwnd_gain;
        }
        if self.mode == Mode::Drain && in_flight <= self.get_target_cwnd(1.0) {
            self.enter_probe_bandwidth_mode(now);
        }
    }

    fn is_min_rtt_expired(&self, now: Instant) -> bool {
        !self.app_limited
            && self
                .probe_rtt_last_started_at
                .map(|last| {
                    if now > last {
                        now - last > Duration::from_secs(10)
                    } else {
                        false
                    }
                })
                .unwrap_or(true)
    }

    fn maybe_enter_or_exit_probe_rtt(
        &mut self,
        now: Instant,
        is_round_start: bool,
        bytes_in_flight: usize,
        _app_limited: bool,
    ) {
        let min_rtt_expired = self.is_min_rtt_expired(now);
        // Enter ProbeRTT if min_rtt expired, not restarting from idle, and not already in ProbeRTT
        // Matches tcp_bbr.c:957-962
        if min_rtt_expired && !self.idle_restart && self.mode != Mode::ProbeRtt {
            // Save cwnd before entering ProbeRTT (matches Linux BBR tcp_bbr.c:960)
            self.save_cwnd();
            self.mode = Mode::ProbeRtt;
            self.pacing_gain = 1.0;
            // Do not decide on the time to exit ProbeRtt until the
            // |bytes_in_flight| is at the target small value.
            self.exit_probe_rtt_at = None;
            self.probe_rtt_last_started_at = Some(now);
        }

        if self.mode == Mode::ProbeRtt {
            if self.exit_probe_rtt_at.is_none() {
                // If the window has reached the appropriate size, schedule exiting
                // ProbeRtt.  The CWND during ProbeRtt is
                // kMinimumCongestionWindow, but we allow an extra packet since QUIC
                // checks CWND before sending a packet.
                if bytes_in_flight < self.get_probe_rtt_cwnd() + MAX_SEGMENT_SIZE {
                    const K_PROBE_RTT_TIME: Duration = Duration::from_millis(200);
                    self.exit_probe_rtt_at = Some(now + K_PROBE_RTT_TIME);
                }
            } else if is_round_start {
                if let Some(exit_time) = self.exit_probe_rtt_at {
                    if now >= exit_time {
                        // Restore cwnd when exiting ProbeRTT (matches Linux BBR tcp_bbr.c:918)
                        self.restore_cwnd();
                        if !self.is_at_full_bandwidth {
                            self.enter_startup_mode();
                        } else {
                            self.enter_probe_bandwidth_mode(now);
                        }
                    }
                }
            }
        }
    }

    fn get_target_cwnd(&self, gain: f32) -> usize {
        let bw = self.max_bandwidth.get_estimate();
        // NOTE(zfc): RTT samples are whole milliseconds, so a sub-ms LAN path reads
        // min_rtt = 0 and the BDP would vanish; floor it at 1 ms.
        let min_rtt_us = self.min_rtt.total_micros().max(1_000);
        let bdp = min_rtt_us * bw;
        let bdpf = bdp as f64;
        let cwnd = ((gain as f64 * bdpf) / 1_000_000f64) as usize;
        // BDP estimate will be zero if no bandwidth samples are available yet.
        if cwnd == 0 {
            return self.init_cwnd;
        }
        cwnd.max(self.min_cwnd)
    }

    fn get_probe_rtt_cwnd(&self) -> usize {
        const K_MODERATE_PROBE_RTT_MULTIPLIER: f32 = 0.75;
        if PROBE_RTT_BASED_ON_BDP {
            return self.get_target_cwnd(K_MODERATE_PROBE_RTT_MULTIPLIER);
        }
        self.min_cwnd
    }

    fn calculate_cwnd(&mut self, bytes_acked: usize) {
        if self.mode == Mode::ProbeRtt {
            return;
        }

        // No packet fully ACKed; just apply caps
        // Matches tcp_bbr.c:526-527
        if bytes_acked == 0 {
            // Enforce minimum cwnd
            if self.cwnd < self.min_cwnd {
                self.cwnd = self.min_cwnd;
            }
            return;
        }

        // Handle recovery and restoration with packet conservation
        // Matches tcp_bbr.c:529-530
        if let Some(new_cwnd) = self.set_cwnd_to_recover_or_restore(
            bytes_acked,
            self.loss_state.lost_bytes,
            self.bytes_in_flight,
        ) {
            self.cwnd = new_cwnd;
            // If packet conservation is active, skip normal cwnd growth
            // and just enforce minimum. Matches tcp_bbr.c:529-530 (goto done)
            if self.packet_conservation {
                if self.cwnd < self.min_cwnd {
                    self.cwnd = self.min_cwnd;
                }
                return;
            }
        }

        // Normal cwnd calculation: compute target cwnd based on BDP
        // Matches tcp_bbr.c:532-538
        let mut target_window = self.get_target_cwnd(self.cwnd_gain);

        // Add ACK aggregation cwnd increment
        // Matches tcp_bbr.c:537
        let bw = self.max_bandwidth.get_estimate();
        target_window = target_window.saturating_add(
            self.ack_aggregation
                .ack_aggregation_cwnd(bw, self.is_at_full_bandwidth),
        );

        // Note: bbr_quantization_budget (tcp_bbr.c:538) is omitted as it's
        // TSO-specific and not applicable to smoltcp

        // Slow start cwnd toward target cwnd
        // Matches tcp_bbr.c:541-545
        if self.is_at_full_bandwidth {
            // Only cut cwnd if we filled the pipe
            self.cwnd = target_window.min(self.cwnd.saturating_add(bytes_acked));
        } else if (self.cwnd < target_window)
            || (self.acked_bytes < self.init_cwnd as u64)
        {
            // If the connection is not yet out of startup phase, do not decrease
            // the window.
            self.cwnd = self.cwnd.saturating_add(bytes_acked);
        }

        // Enforce the limits on the congestion window.
        // Matches tcp_bbr.c:545
        if self.cwnd < self.min_cwnd {
            self.cwnd = self.min_cwnd;
        }
    }

    fn calculate_recovery_window(
        &mut self,
        bytes_acked: usize,
        bytes_lost: usize,
        in_flight: usize,
    ) {
        if !self.recovery_state.in_recovery() {
            return;
        }
        // Set up the initial recovery window.
        if self.recovery_window == 0 {
            self.recovery_window = self.min_cwnd.max(in_flight.saturating_add(bytes_acked));
            return;
        }

        // Remove losses from the recovery window, while accounting for a potential
        // integer underflow.
        if self.recovery_window >= bytes_lost {
            self.recovery_window -= bytes_lost;
        } else {
            self.recovery_window = MAX_SEGMENT_SIZE;
        }
        // In CONSERVATION mode, just subtracting losses is sufficient.  In GROWTH,
        // release additional |bytes_acked| to achieve a slow-start-like behavior.
        if self.recovery_state == RecoveryState::Growth {
            self.recovery_window = self.recovery_window.saturating_add(bytes_acked);
        }

        // Sanity checks.  Ensure that we always allow to send at least an MSS or
        // |bytes_acked| in response, whichever is larger.
        self.recovery_window = self
            .recovery_window
            .max(in_flight.saturating_add(bytes_acked))
            .max(self.min_cwnd);
    }

    /// <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control#section-4.3.2.2>
    /// <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control#section-4.3.2.2>
    fn check_if_full_bw_reached(&mut self) {
        if self.app_limited {
            return;
        }
        let target = (self.bw_at_last_round as f64 * K_STARTUP_GROWTH_TARGET as f64) as u64;
        let bw = self.max_bandwidth.get_estimate();
        if bw >= target {
            self.bw_at_last_round = bw;
            self.round_wo_bw_gain = 0;
            // Reset ACK aggregation tracking when bandwidth increases
            self.ack_aggregation.extra_acked = [0, 0];
            self.ack_aggregation.extra_acked_win_rtts = 0;
            return;
        }

        self.round_wo_bw_gain += 1;
        // NOTE(zfc): do NOT exit STARTUP merely because we entered loss recovery.
        // Linux BBRv1 exits STARTUP only on sustained no-bandwidth-growth (≥3 rounds);
        // exiting on the first loss makes BBR loss-INTOLERANT — the opposite of its
        // purpose. On lossy paths (e.g. CN→cloud WG-inbound, ~kpps retransmits where
        // kernel BBR still does 600M+) the original `|| in_recovery()` clause locked
        // BtlBw/cwnd at the startup-reached value → single-flow collapsed to ~cwnd/RTT
        // (~20Mbps). Probe through loss; let the no-growth counter end STARTUP.
        if self.round_wo_bw_gain >= K_ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP as u64 {
            self.is_at_full_bandwidth = true;
        }
    }

    fn on_ack_impl(&mut self, now: Instant, len: usize, rtt: &RttEstimator) {
        let bytes = len as u64;
        // NOTE(zfc): round / recovery accounting is in ACKed *bytes* against a
        // target of "everything in flight when the round started has been ACKed"
        // (`round_end_mark`). The original port counted `on_ack` and
        // `post_transmit` calls as packet numbers; one ACK routinely covers several
        // segments (delayed / cumulative ACKs) and retransmits add sends, so the
        // ACK count drifts ever further behind the send count and rounds stop
        // ending — ProbeRTT never exits, the BtlBw filter window never advances.
        self.max_acked_packet_number = self.max_acked_packet_number.saturating_add(bytes);

        // Update bandwidth estimation with app_limited state
        self.max_bandwidth.set_sample_interval(rtt.min_rtt());
        self.max_bandwidth
            .on_ack(now, now, bytes, self.round_count, self.app_limited);
        self.acked_bytes += bytes;

        // Update min_rtt from the RttEstimator's windowed minimum
        // The RttEstimator now properly tracks the minimum RTT over a 10-second window
        // and handles expiration, matching Linux BBR behavior
        let current_min_rtt = rtt.min_rtt();
        if self.min_rtt == Duration::ZERO || self.min_rtt > current_min_rtt {
            self.min_rtt = current_min_rtt;
        }

        // End of acks processing
        let bytes_acked = self.max_bandwidth.bytes_acked_this_window() as usize;
        self.max_bandwidth
            .end_acks(self.round_count, self.app_limited);

        // Track round start
        // Matches tcp_bbr.c:767, 772-777
        self.round_start = false;
        if bytes_acked > 0 {
            let is_round_start =
                self.max_acked_packet_number >= self.current_round_trip_end_packet_number;
            if is_round_start {
                self.round_start = true;
                self.current_round_trip_end_packet_number = self.round_end_mark();
                self.round_count += 1;
                // Reset packet conservation on round start
                // Matches tcp_bbr.c:776
                self.packet_conservation = false;
            }
        }

        self.update_recovery_state(self.round_start);

        // Update ACK aggregation tracking
        // Matches tcp_bbr.c:1019 (bbr_update_ack_aggregation call in bbr_update_model)
        self.ack_aggregation.update_ack_aggregation(
            bytes_acked as u64,
            now,
            self.round_start,
            self.max_bandwidth.get_estimate(),
            self.cwnd,
        );

        if self.mode == Mode::ProbeBw {
            self.update_gain_cycle_phase(now, self.bytes_in_flight);
        }

        if self.round_start && !self.is_at_full_bandwidth {
            self.check_if_full_bw_reached();
        }

        self.maybe_exit_startup_or_drain(now, self.bytes_in_flight);

        self.maybe_enter_or_exit_probe_rtt(
            now,
            self.round_start,
            self.bytes_in_flight,
            self.app_limited,
        );

        // After the model is updated, recalculate the congestion window.
        // NOTE(zfc): pacing rate is intentionally NOT computed — pacing is disabled
        // for this fork (cwnd-only / ACK-clocked; see `pacing_rate()`), so the old
        // per-ACK `calculate_pacing_rate()` was pure dead work and is removed.
        self.calculate_cwnd(bytes_acked);
        self.calculate_recovery_window(
            bytes_acked,
            self.loss_state.lost_bytes,
            self.bytes_in_flight,
        );

        // Reset idle_restart after processing new data delivery
        // Matches tcp_bbr.c:983-984: "Restart after idle ends only once we process a new S/ACK for data"
        if bytes_acked > 0 {
            self.idle_restart = false;
        }

        self.prev_in_flight_count = self.bytes_in_flight;
        self.loss_state.reset();
    }

    /// ACKed-bytes mark at which everything currently in flight has been ACKed.
    fn round_end_mark(&self) -> u64 {
        self.max_acked_packet_number
            .saturating_add(self.bytes_in_flight as u64)
    }

    fn on_transmit_impl(&mut self, now: Instant, len: usize) {
        let bytes = len as u64;
        let packet_number = self.max_sent_packet_number + 1;
        self.max_sent_packet_number = packet_number;
        self.max_bandwidth.on_sent(now, bytes);
    }
}

impl Controller for Bbr {
    fn window(&self) -> usize {
        // NOTE(zfc): do NOT cap cwnd to the Chromium-style packet-conservation
        // `recovery_window` on loss. On a persistently lossy path (CN→cloud WG
        // inbound, ~kpps retransmits where kernel BBR still does 600M+) a loss occurs
        // almost every round, so the connection never leaves recovery and cwnd stays
        // pinned at ~in-flight (~one BDP) → single-flow collapses to ~cwnd/RTT
        // (~20Mbps). Linux BBRv1 keeps cwnd loss-independent (= cwnd_gain × BDP) and
        // relies on ProbeRTT/BtlBw, not loss, for sizing. Use the BBR target cwnd
        // directly so loss tolerance actually works. See zfc
        // docs/design/wireguard-inbound-throughput.md.
        // ProbeRTT only ever lowers the window (Linux `bbr_set_cwnd`: `min(cwnd,
        // bbr_cwnd_min_target)`), so an RTO collapse is not bypassed while probing.
        let cwnd = if self.mode == Mode::ProbeRtt {
            self.get_probe_rtt_cwnd().min(self.cwnd)
        } else {
            self.cwnd
        };
        cwnd.min(self.rwnd)
    }

    fn set_remote_window(&mut self, remote_window: usize) {
        if self.rwnd < remote_window {
            self.rwnd = remote_window;
        }
    }

    fn on_ack(&mut self, now: Instant, len: usize, in_flight: usize, rtt: &RttEstimator) {
        self.bytes_in_flight = in_flight;
        self.on_ack_impl(now, len, rtt);
    }

    // NOTE(zfc): fast-retransmit loss (3 dup-ACKs) and each further dup-ACK keep the
    // fork's loss-tolerant semantics: they only feed the recovery-state machine, the
    // BBR target cwnd is not cut (see `window()`).
    fn on_loss(&mut self, _now: Instant, _in_flight: usize) {
        self.loss_state.lost_bytes = self.loss_state.lost_bytes.saturating_add(1);
    }

    fn on_dup_ack(&mut self, _now: Instant, _len: usize, _in_flight: usize) {
        self.loss_state.lost_bytes = self.loss_state.lost_bytes.saturating_add(1);
    }

    /// NOTE(zfc): a retransmission timeout means the ACK clock is gone and every
    /// outstanding byte is presumed lost; the socket rewinds and resends from
    /// `snd_una`. Loss tolerance must not extend to this case: resending the whole
    /// (unpaced) window in one go into a congested bottleneck re-creates the loss
    /// that caused the timeout (#637). Collapse to the minimum window and let
    /// `calculate_cwnd` slow-start back toward the BBR target on returning ACKs
    /// (Linux: `tcp_enter_loss` sets cwnd to in-flight + 1). The pre-RTO cwnd is
    /// deliberately not restored on recovery exit: without pacing that restore is
    /// itself a line-rate burst of up to cwnd_gain × BDP.
    fn on_rto(&mut self, _now: Instant, _in_flight: usize) {
        self.loss_state.lost_bytes = self.loss_state.lost_bytes.saturating_add(1);
        self.cwnd = self.min_cwnd;
        self.prior_cwnd = self.min_cwnd;
        self.packet_conservation = false;
    }

    fn pre_transmit(&mut self, _now: Instant) {
        // BBR doesn't need pre-transmission processing
    }

    fn post_transmit(&mut self, now: Instant, len: usize) {
        self.on_transmit_impl(now, len);
    }

    fn set_mss(&mut self, mss: usize) {
        self.min_cwnd = mss * 2;
        if self.cwnd < self.min_cwnd {
            self.cwnd = self.min_cwnd;
        }
    }

    fn on_send_ready(&mut self, now: Instant, bytes_available: usize) {
        // Detect idle restart: transmission starting when app_limited
        // Matches tcp_bbr.c:337-348 (CA_EVENT_TX_START)
        if self.app_limited && bytes_available > 0 {
            self.idle_restart = true;
            // Reset ACK aggregation epoch on idle restart
            self.ack_aggregation.ack_epoch_mstamp = Some(now);
            self.ack_aggregation.ack_epoch_acked = 0;
            // Note: Pacing rate adjustment happens in set_pacing_rate() calls
            // which are made during normal cwnd/pacing updates
        }

        // Track app-limited state: true when bytes_available < cwnd
        // This follows Quinn's approach where app_limited indicates the application
        // doesn't have enough data to fill the congestion window.
        let cwnd = self.window();
        self.app_limited = bytes_available < cwnd;
    }

    fn pacing_rate(&self) -> u64 {
        // NOTE(zfc): fine-grained pacing is DISABLED for this fork (return 0 →
        // tcp.rs treats the socket as cwnd-only / ACK-clocked).
        //
        // The netstack runs on a tokio loop whose wakes are ~1 ms at best and several
        // ms apart on a busy single-core worker, while the socket only lets pacing
        // catch up `pacing_max_backlog_us` (2 ms) per wake. A paced flow therefore
        // sends well below its pacing rate, the delivery-rate samples follow it down
        // and BtlBw decays. #637 re-measured it with the fixed estimator (netem rig,
        // 1-vCPU worker): pacing cut the loss storm on a 450 Mbit / 200 KB bottleneck
        // (80 ms: 62 → 110 Mbps) but halved loss-free throughput at 80 ms (~570 →
        // ~240 Mbps) and cost ~17% at 12 ms — a net loss. cwnd_gain × BDP still
        // probes bandwidth through the in-flight headroom, and SACK recovery absorbs
        // the resulting losses. See zfc docs/design/wireguard-inbound-throughput.md
        // and Gitea #637.
        0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum Mode {
    // Startup phase of the connection.
    Startup,
    // After achieving the highest possible bandwidth during the startup, lower
    // the pacing rate in order to drain the queue.
    Drain,
    // Cruising mode.
    ProbeBw,
    // Temporarily slow down sending in order to empty the buffer and measure
    // the real minimum RTT.
    ProbeRtt,
}

// Indicates how the congestion control limits the amount of bytes in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum RecoveryState {
    // Do not limit.
    NotInRecovery,
    // Allow an extra outstanding byte for each byte acknowledged.
    Conservation,
    // Allow two extra outstanding bytes for each byte acknowledged (slow
    // start).
    Growth,
}

impl RecoveryState {
    pub fn in_recovery(&self) -> bool {
        !matches!(self, RecoveryState::NotInRecovery)
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct AckAggregationState {
    // Windowed max filter for tracking maximum extra acked
    // Matches tcp_bbr.c:123 (extra_acked[2])
    extra_acked: [u64; 2],
    // Current window index for extra_acked array
    // Matches tcp_bbr.c:126 (extra_acked_win_idx)
    extra_acked_win_idx: usize,
    // Age of extra_acked window in round trips
    // Matches tcp_bbr.c:125 (extra_acked_win_rtts)
    extra_acked_win_rtts: u32,
    // Start time of current ACK aggregation epoch
    // Matches tcp_bbr.c:122 (ack_epoch_mstamp)
    ack_epoch_mstamp: Option<Instant>,
    // Packets ACKed in current sampling epoch
    // Matches tcp_bbr.c:124 (ack_epoch_acked)
    ack_epoch_acked: u64,
}

impl AckAggregationState {
    /// Return maximum extra acked in past k-2k round trips, where k = BBR_EXTRA_ACKED_WIN_RTTS
    /// Matches Linux BBR bbr_extra_acked() (tcp_bbr.c:233-238)
    fn extra_acked(&self) -> u64 {
        self.extra_acked[0].max(self.extra_acked[1])
    }

    /// Estimates the windowed max degree of ACK aggregation.
    /// Matches Linux BBR bbr_update_ack_aggregation() (tcp_bbr.c:817-863)
    fn update_ack_aggregation(
        &mut self,
        newly_acked_bytes: u64,
        now: Instant,
        round_start: bool,
        max_bandwidth: u64,
        cwnd: usize,
    ) {
        // Check if we should skip (no gain configured or invalid input)
        // Matches tcp_bbr.c:824-826
        if BBR_EXTRA_ACKED_GAIN == 0 || newly_acked_bytes == 0 {
            return;
        }

        // Advance the windowed max filter on round start
        // Matches tcp_bbr.c:828-836
        if round_start {
            self.extra_acked_win_rtts = (self.extra_acked_win_rtts + 1).min(0x1F);
            if self.extra_acked_win_rtts >= BBR_EXTRA_ACKED_WIN_RTTS {
                self.extra_acked_win_rtts = 0;
                self.extra_acked_win_idx = if self.extra_acked_win_idx == 0 { 1 } else { 0 };
                self.extra_acked[self.extra_acked_win_idx] = 0;
            }
        }

        // Compute how many bytes we expected to be delivered over this epoch
        // Matches tcp_bbr.c:839-842
        let expected_acked = if let Some(epoch_start) = self.ack_epoch_mstamp {
            if now > epoch_start {
                let epoch_us = (now - epoch_start).total_micros();
                max_bandwidth * epoch_us / 1_000_000
            } else {
                0
            }
        } else {
            0
        };

        // Reset the aggregation epoch if ACK rate is below expected rate or
        // epoch has become too large (stale)
        // Matches tcp_bbr.c:844-854
        if self.ack_epoch_acked <= expected_acked
            || self.ack_epoch_acked + newly_acked_bytes >= BBR_ACK_EPOCH_ACKED_RESET_THRESH
        {
            self.ack_epoch_acked = 0;
            self.ack_epoch_mstamp = Some(now);
            // expected_acked = 0 after reset (implicitly used below)
            // Matches tcp_bbr.c:853
        }

        // Compute excess data delivered, beyond what was expected
        // Matches tcp_bbr.c:856-862
        self.ack_epoch_acked = (self.ack_epoch_acked + newly_acked_bytes).min(0xFFFFF);

        let extra_acked = if self.ack_epoch_acked > expected_acked {
            self.ack_epoch_acked - expected_acked
        } else {
            0
        };

        // Clamp by cwnd
        let extra_acked = extra_acked.min(cwnd as u64);

        // Update windowed max
        if extra_acked > self.extra_acked[self.extra_acked_win_idx] {
            self.extra_acked[self.extra_acked_win_idx] = extra_acked;
        }
    }

    /// Find the cwnd increment based on estimate of ack aggregation
    /// Matches Linux BBR bbr_ack_aggregation_cwnd() (tcp_bbr.c:457-470)
    fn ack_aggregation_cwnd(&self, bw: u64, is_at_full_bandwidth: bool) -> usize {
        if BBR_EXTRA_ACKED_GAIN == 0 || !is_at_full_bandwidth {
            return 0;
        }

        // max_aggr_cwnd = bw * 100ms
        // Matches tcp_bbr.c:462-463
        let max_aggr_cwnd = (bw * BBR_EXTRA_ACKED_MAX_US / 1_000_000) as usize;

        // aggr_cwnd = (gain * extra_acked) >> BBR_SCALE
        // Matches tcp_bbr.c:464-465
        let extra = self.extra_acked();
        let aggr_cwnd = ((BBR_EXTRA_ACKED_GAIN as u64 * extra) >> BBR_SCALE) as usize;

        // Clamp by max
        // Matches tcp_bbr.c:466
        aggr_cwnd.min(max_aggr_cwnd)
    }
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct LossState {
    lost_bytes: usize,
}

impl LossState {
    pub fn reset(&mut self) {
        self.lost_bytes = 0;
    }

    pub fn has_losses(&self) -> bool {
        self.lost_bytes != 0
    }
}

// The gain used for the STARTUP, equal to 2/ln(2).
const K_DEFAULT_HIGH_GAIN: f32 = 2.885;
// The newly derived CWND gain for STARTUP, 2.
const K_DERIVED_HIGH_CWNDGAIN: f32 = 2.0;
// The cycle of gains used during the ProbeBw stage.
const K_PACING_GAIN: [f32; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

const K_STARTUP_GROWTH_TARGET: f32 = 1.25;
const K_ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP: u8 = 3;

// ACK aggregation constants
// Gain factor for adding extra_acked to target cwnd
// Matches tcp_bbr.c:196 (bbr_extra_acked_gain = BBR_UNIT = 256)
const BBR_EXTRA_ACKED_GAIN: u32 = 256;
// Window length of extra_acked window in round trips
// Matches tcp_bbr.c:198
const BBR_EXTRA_ACKED_WIN_RTTS: u32 = 5;
// Max allowed value for ack_epoch_acked, after which sampling epoch is reset
// Matches tcp_bbr.c:200
const BBR_ACK_EPOCH_ACKED_RESET_THRESH: u64 = 1u64 << 20;
// Time period for clamping cwnd increment due to ack aggregation (100ms in microseconds)
// Matches tcp_bbr.c:202
const BBR_EXTRA_ACKED_MAX_US: u64 = 100 * 1000;
// BBR_SCALE for gain calculations
// Matches tcp_bbr.c:77 (BBR_SCALE = 8, BBR_UNIT = 1 << 8 = 256)
const BBR_SCALE: u32 = 8;

const MAX_SEGMENT_SIZE: usize = 1460;

const PROBE_RTT_BASED_ON_BDP: bool = true;
const DRAIN_TO_TARGET: bool = true;


#[cfg(test)]
mod test {
    use super::*;

    const MSS: usize = 1400;

    fn rtte() -> RttEstimator {
        RttEstimator::default()
    }

    #[test]
    fn rto_collapses_window_to_min() {
        let mut bbr = Bbr::new();
        bbr.set_mss(MSS);
        bbr.set_remote_window(64 * 1024 * 1024);
        bbr.cwnd = 4 * 1024 * 1024;
        assert_eq!(bbr.window(), 4 * 1024 * 1024);

        bbr.on_rto(Instant::from_millis(1000), 4 * 1024 * 1024);
        assert_eq!(bbr.window(), 2 * MSS, "RTO must collapse cwnd to the minimum window");
    }

    /// Drive `rounds` RTTs of an ACK clock: each RTT the whole current window is
    /// ACKed in MSS-sized ACKs that all carry the same timestamp (the host netstack
    /// stamps a batch of received segments with one `now`).
    fn ack_clock(bbr: &mut Bbr, rtt: &mut RttEstimator, start_ms: i64, rtt_ms: i64, rounds: i64) -> Vec<usize> {
        let mut windows = std::vec::Vec::new();
        for r in 0..rounds {
            let now = Instant::from_millis(start_ms + rtt_ms * (r + 1));
            rtt.sample(rtt_ms as u32, now);
            let n = (bbr.window() / MSS).max(1);
            for _ in 0..n {
                bbr.post_transmit(now, MSS);
            }
            for _ in 0..n {
                bbr.on_ack(now, MSS, 0, rtt);
            }
            windows.push(bbr.window());
        }
        windows
    }

    #[test]
    fn rto_window_regrows_on_acks_without_jumping_back() {
        let mut bbr = Bbr::new();
        bbr.set_mss(MSS);
        bbr.set_remote_window(64 * 1024 * 1024);
        bbr.cwnd = 4 * 1024 * 1024;
        bbr.on_rto(Instant::from_millis(1000), 4 * 1024 * 1024);

        let mut rtt = rtte();
        let mut prev = bbr.window();
        for w in ack_clock(&mut bbr, &mut rtt, 1000, 10, 40) {
            // ACK-clocked regrowth: at most doubling per RTT (every acked byte may be
            // sent twice), never a jump back to the pre-RTO window.
            assert!(w <= prev * 2 + MSS, "window jumped ({prev} -> {w})");
            prev = w;
        }
        assert!(prev >= 256 * 1024, "window must re-grow after RTO, got {prev}");
    }

    #[test]
    fn bandwidth_estimate_survives_batched_acks() {
        // 100 MSS ACKed per 10 ms RTT, all ACKs of an RTT sharing one timestamp:
        // delivery rate = 100 * 1400 B / 10 ms = 14 MB/s.
        let mut bbr = Bbr::new();
        bbr.set_mss(MSS);
        bbr.set_remote_window(64 * 1024 * 1024);
        let mut rtt = rtte();
        for r in 0..20i64 {
            let now = Instant::from_millis(1000 + 10 * (r + 1));
            rtt.sample(10, now);
            for _ in 0..100 {
                bbr.post_transmit(now, MSS);
            }
            for _ in 0..100 {
                bbr.on_ack(now, MSS, 0, &rtt);
            }
        }
        let bw = bbr.max_bandwidth.get_estimate();
        let want = 100 * MSS as u64 * 100; // bytes per second
        assert!(bw >= want * 8 / 10 && bw <= want * 12 / 10, "bw estimate {bw}, want ~{want}");
    }

    /// Fixed-capacity, ACK-clocked pipe: the sender tops in-flight up to the window,
    /// the pipe delivers at most `cap` bytes per RTT (the rest stays queued), and the
    /// ACKs of one RTT share a timestamp and report the real remaining in-flight.
    fn pipe(bbr: &mut Bbr, rtt: &mut RttEstimator, rtt_ms: i64, cap: usize, rounds: i64) {
        let mut in_flight = 0usize;
        for r in 0..rounds {
            let now = Instant::from_millis(1000 + rtt_ms * (r + 1));
            rtt.sample(rtt_ms as u32, now);
            while in_flight + MSS <= bbr.window().max(MSS) {
                bbr.post_transmit(now, MSS);
                in_flight += MSS;
            }
            // Delayed ACKs: one ACK per two segments.
            let mut delivered = 0;
            while delivered + 2 * MSS <= cap && in_flight >= 2 * MSS {
                delivered += 2 * MSS;
                in_flight -= 2 * MSS;
                bbr.on_ack(now, 2 * MSS, in_flight, rtt);
            }
        }
    }

    #[test]
    fn probe_rtt_exits_and_window_tracks_bdp() {
        // 100 MSS per 10 ms RTT (14 MB/s); 30 s covers several 10 s ProbeRTT cycles.
        let cap = 100 * MSS;
        let mut bbr = Bbr::new();
        bbr.set_mss(MSS);
        bbr.set_remote_window(64 * 1024 * 1024);
        let mut rtt = rtte();
        pipe(&mut bbr, &mut rtt, 10, cap, 3000);
        assert_ne!(bbr.mode, Mode::ProbeRtt, "stuck in ProbeRTT");
        let bw = bbr.max_bandwidth.get_estimate();
        let want = cap as u64 * 100;
        assert!(bw >= want * 8 / 10, "BtlBw decayed: {bw}, want ~{want}");
        assert!(bbr.window() >= cap, "window below BDP: {} < {cap}", bbr.window());
    }

    #[test]
    fn fast_retransmit_loss_keeps_window() {
        let mut bbr = Bbr::new();
        bbr.set_mss(MSS);
        bbr.set_remote_window(64 * 1024 * 1024);
        bbr.cwnd = 4 * 1024 * 1024;
        bbr.on_loss(Instant::from_millis(1000), 4 * 1024 * 1024);
        bbr.on_dup_ack(Instant::from_millis(1000), MSS, 4 * 1024 * 1024);
        assert_eq!(bbr.window(), 4 * 1024 * 1024, "BBR stays loss-tolerant on dup-ACK loss");
    }
}
