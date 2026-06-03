use crate::socket::tcp::RttEstimator;
use crate::time::{Duration, Instant};

use super::Controller;

/// Hysteria2-style "Brutal" congestion control: send at a fixed, configured rate
/// regardless of loss. Unlike Reno/Cubic/BBR, the congestion window is *not* the
/// limiter — it is kept wide (BDP × gain) and the actual send rate is enforced
/// entirely by smoltcp's pacing layer (`pacing_rate()` → `pacing_next_send_at`).
///
/// Phase 1 (this impl): **no loss compensation** (`ack_rate = 1`) — `pacing_rate()`
/// returns the raw target rate. The loss-inflation form (`rate / ack_rate`, capped
/// ~1.25×, à la hysteria2 / TCP-Brutal) can be layered on later, once the
/// `Controller` trait carries lost-byte signals (today `on_retransmit` /
/// `on_duplicate_ack` carry no byte count, so a precise `ack_rate` is not derivable).
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Brutal {
    /// Target send rate in bytes/sec. 0 until [`set_rate`](Self::set_rate) is called
    /// → pacing disabled, behaves cwnd-only as a safe fallback for the brief window
    /// between `set_congestion_control(Brutal)` and the rate injection.
    rate_bytes_per_sec: u64,
    /// Maximum segment size, set by the socket via [`Controller::set_mss`].
    mss: usize,
    /// Smoothed RTT, used to size the congestion window (BDP). Falls back to
    /// [`DEFAULT_RTT`] until the first measurement arrives so the window is never
    /// tiny on cold start.
    rtt: Duration,
}

/// RTT assumption before the first sample — keeps the initial window non-trivial so
/// the connection can ramp before RTT is known.
const DEFAULT_RTT: Duration = Duration::from_millis(100);
/// Congestion-window gain over the BDP (headroom so pacing, not cwnd, is the limiter).
const WINDOW_GAIN: u64 = 2;
/// Absolute floor for the window so it is never 0 / tiny on cold start.
const MIN_WINDOW: usize = 64 * 1024;

impl Brutal {
    pub fn new() -> Self {
        Brutal {
            rate_bytes_per_sec: 0,
            mss: 1480,
            rtt: DEFAULT_RTT,
        }
    }

    /// Inject the fixed target down rate (bytes/sec). Called by
    /// `Socket::set_brutal_rate_bytes_per_sec` right after selecting Brutal.
    pub(super) fn set_rate(&mut self, bytes_per_sec: u64) {
        self.rate_bytes_per_sec = bytes_per_sec;
    }
}

impl Default for Brutal {
    fn default() -> Self {
        Self::new()
    }
}

impl Controller for Brutal {
    fn window(&self) -> usize {
        // cwnd must not be the limiter — size it to BDP × gain, floored. With no rate
        // yet (pre-injection) fall back to the floor.
        let floor = self.mss.saturating_mul(10).max(MIN_WINDOW);
        if self.rate_bytes_per_sec == 0 {
            return floor;
        }
        let rtt_ms = self.rtt.total_millis().max(1);
        let bdp = self.rate_bytes_per_sec.saturating_mul(rtt_ms) / 1000;
        let win = bdp.saturating_mul(WINDOW_GAIN);
        usize::try_from(win).unwrap_or(usize::MAX).max(floor)
    }

    fn on_ack(&mut self, _now: Instant, _len: usize, rtt: &RttEstimator) {
        // Track RTT for BDP sizing. (Loss is intentionally not tracked in phase 1.)
        if let Some(srtt) = rtt.smoothed_rtt() {
            self.rtt = srtt;
        }
    }

    fn set_mss(&mut self, mss: usize) {
        self.mss = mss;
    }

    fn pacing_rate(&self) -> u64 {
        // Fixed-rate pacing: smoltcp's pacing layer turns this into a per-packet send
        // cadence (`delay = segment_len * 1e6 / pacing_rate`). 0 → pacing disabled
        // (cwnd-only fallback before the rate is injected).
        self.rate_bytes_per_sec
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn pacing_rate_tracks_set_rate() {
        let mut b = Brutal::new();
        assert_eq!(b.pacing_rate(), 0, "no rate → pacing disabled");
        b.set_rate(12_500_000); // 100 Mbps in bytes/sec
        assert_eq!(b.pacing_rate(), 12_500_000);
    }

    #[test]
    fn window_is_never_below_floor() {
        let mut b = Brutal::new();
        b.set_mss(1480);
        // No rate yet → floor.
        assert!(b.window() >= MIN_WINDOW);
        // With a rate, window ≈ BDP × gain and still ≥ floor.
        b.set_rate(12_500_000);
        let bdp = 12_500_000u64 * 100 / 1000; // DEFAULT_RTT = 100ms
        let expect = (bdp * WINDOW_GAIN) as usize;
        assert_eq!(b.window(), expect.max(MIN_WINDOW));
    }
}
