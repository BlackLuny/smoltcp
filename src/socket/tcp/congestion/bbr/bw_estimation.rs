use crate::time::{Duration, Instant};

use super::min_max::MinMax;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct BandwidthEstimation {
    total_acked: u64,
    prev_total_acked: u64,
    acked_time: Option<Instant>,
    prev_acked_time: Option<Instant>,
    total_sent: u64,
    prev_total_sent: u64,
    sent_time: Option<Instant>,
    prev_sent_time: Option<Instant>,
    max_filter: MinMax,
    acked_at_last_window: u64,
    /// NOTE(zfc): start of the current delivery-rate sampling interval
    /// (timestamp, `total_acked` at that time).
    interval_start: Option<(Instant, u64)>,
    /// NOTE(zfc): minimum sampling interval (≈ min RTT, floored to 1 ms).
    sample_interval: Duration,
}

impl Default for BandwidthEstimation {
    fn default() -> Self {
        BandwidthEstimation {
            total_acked: 0,
            prev_total_acked: 0,
            acked_time: None,
            prev_acked_time: None,
            total_sent: 0,
            prev_total_sent: 0,
            sent_time: None,
            prev_sent_time: None,
            max_filter: MinMax::new(10),
            acked_at_last_window: 0,
            interval_start: None,
            sample_interval: MIN_SAMPLE_INTERVAL,
        }
    }
}

/// Floor for the sampling interval: `now` has millisecond-ish effective resolution
/// on the host timer, and a sub-RTT LAN path would otherwise sample per batch.
const MIN_SAMPLE_INTERVAL: Duration = Duration::from_millis(1);

impl BandwidthEstimation {
    pub fn on_sent(&mut self, now: Instant, bytes: u64) {
        self.prev_total_sent = self.total_sent;
        self.total_sent += bytes;
        self.prev_sent_time = self.sent_time;
        self.sent_time = Some(now);
    }

    /// NOTE(zfc): set the delivery-rate sampling interval (the BBR min RTT).
    pub fn set_sample_interval(&mut self, min_rtt: Duration) {
        self.sample_interval = min_rtt.max(MIN_SAMPLE_INTERVAL);
    }

    /// NOTE(zfc): delivery rate is sampled over an interval of at least one min RTT
    /// (bytes ACKed during the interval / elapsed time), not per ACK. The host
    /// netstack stamps a whole batch of received segments with a single `now`, so a
    /// per-ACK rate (one ACK's bytes over the gap since the previous ACK) reads 0 for
    /// every ACK in a batch but the first, and the first one divides a single ACK's
    /// bytes by the whole inter-batch gap — BtlBw collapses to a small fraction of
    /// the real rate. That was harmless while the socket ignored cwnd, but with cwnd
    /// enforced (#637) it pins throughput to that underestimate.
    pub fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        bytes: u64,
        round: u64,
        app_limited: bool,
    ) {
        let acked_before = self.total_acked;
        self.prev_total_acked = self.total_acked;
        self.total_acked += bytes;
        self.prev_acked_time = self.acked_time;
        self.acked_time = Some(now);

        let (start, start_acked) = match self.interval_start {
            Some(s) => s,
            None => {
                self.interval_start = Some((now, acked_before));
                return;
            }
        };
        if now < start {
            self.interval_start = Some((now, acked_before));
            return;
        }
        let elapsed = now - start;
        if elapsed < self.sample_interval {
            return;
        }
        let Some(bandwidth) =
            BandwidthEstimation::bw_from_delta(self.total_acked - start_acked, elapsed)
        else {
            return;
        };
        self.interval_start = Some((now, self.total_acked));
        // Linux `bbr_update_bw`: app-limited samples only count if they raise the max.
        if !app_limited || bandwidth >= self.max_filter.get() {
            self.max_filter.update_max(round, bandwidth);
        }
    }

    pub fn bytes_acked_this_window(&self) -> u64 {
        self.total_acked - self.acked_at_last_window
    }

    pub fn end_acks(&mut self, _current_round: u64, _app_limited: bool) {
        self.acked_at_last_window = self.total_acked;
    }

    pub fn get_estimate(&self) -> u64 {
        self.max_filter.get()
    }

    pub const fn bw_from_delta(bytes: u64, delta: Duration) -> Option<u64> {
        let window_duration_micros = delta.total_micros();
        if window_duration_micros == 0 {
            return None;
        }
        let bytes_per_second = bytes * 1_000_000 / window_duration_micros;
        Some(bytes_per_second)
    }
}
