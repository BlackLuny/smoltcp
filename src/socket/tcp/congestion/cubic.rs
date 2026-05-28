use crate::{socket::tcp::RttEstimator, time::Instant};

use super::Controller;

// Constants for the Cubic congestion control algorithm.
// See RFC 9438.
const BETA_CUBIC: f64 = 0.7;
const C: f64 = 0.4;
// RFC 9438 §4.3: α_cubic = 3(1-β)/(1+β). ~0.5294 for β=0.7.
const ALPHA_CUBIC: f64 = 3.0 * (1.0 - BETA_CUBIC) / (1.0 + BETA_CUBIC);

const DEFAULT_MSS: usize = 1024;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Cubic {
    w_max: usize, // window size prior to loss
    cwnd: usize,
    min_cwnd: usize,
    ssthresh: usize,
    rwnd: usize,
    k: f64,            // cubic curve offset in seconds; depends only on w_max and min_cwnd
    w_est: f64,        // RFC 9438 §4.3 reno-friendly window, integrated per ACK
    cwnd_prior: usize, // cwnd at the most recent congestion event; gates α_cubic

    recovery_start: Option<Instant>,
    in_fast_recovery: bool,
    idle_start: Option<Instant>, // RFC 9438 §4.2: when in-flight last hit 0
}

impl Cubic {
    pub fn new() -> Cubic {
        let mut cubic = Cubic {
            w_max: DEFAULT_MSS * 2,
            cwnd: DEFAULT_MSS * 2,
            min_cwnd: DEFAULT_MSS * 2,
            rwnd: 64 * DEFAULT_MSS,
            ssthresh: usize::MAX,
            k: 0.0,
            w_est: (DEFAULT_MSS * 2) as f64,
            cwnd_prior: DEFAULT_MSS * 2,

            recovery_start: None,
            in_fast_recovery: false,
            idle_start: None,
        };
        cubic.recompute_k();
        cubic
    }

    // K = cbrt(w_max * (1 - beta) / C) ^ 1/3
    fn recompute_k(&mut self) {
        let c_as_bytes = C * self.min_cwnd as f64;
        let k3 = (self.w_max as f64) * (1.0 - BETA_CUBIC) / c_as_bytes;
        self.k = cube_root(k3).unwrap_or(0.0);
    }

    // RFC 9438 §4.2: subtract the most recent idle period from t by sliding
    // recovery_start forward by the idle duration.
    fn absorb_idle(&mut self, now: Instant) {
        if let (Some(idle), Some(start)) = (self.idle_start, self.recovery_start)
            && now >= idle
        {
            self.recovery_start = Some(start + (now - idle));
        }
        self.idle_start = None;
    }
}

impl Controller for Cubic {
    fn window(&self) -> usize {
        self.cwnd
    }

    fn on_ack(&mut self, now: Instant, len: usize, in_flight: usize, rtt: &RttEstimator) {
        let segment = len.min(self.min_cwnd);

        self.absorb_idle(now);

        if in_flight == 0 {
            self.idle_start = Some(now);
        }

        // First new-data-ack exits fast recovery and deflates `cwnd`
        if self.in_fast_recovery {
            self.in_fast_recovery = false;
            self.cwnd = self.ssthresh;
            self.w_est = self.cwnd as f64;
            return;
        } else if self.cwnd < self.ssthresh {
            // Slow start: increase `cwnd` by 1 MSS per ACK.
            self.cwnd = self
                .cwnd
                .saturating_add(segment)
                .min(self.rwnd)
                .max(self.min_cwnd);
            return;
        }

        // ca: RFC 9438 §4.2 and §4.3: Calculate W_cubic and W_est. Use whichever grows faster.
        let recovery_start = match self.recovery_start {
            Some(t) => t,
            None => {
                // RFC 9438 §4.8: set W_max = cwnd and K = 0 at start of CA
                self.w_max = self.cwnd;
                self.k = 0.0;
                self.w_est = self.cwnd as f64;
                self.recovery_start = Some(now);
                now
            }
        };

        // Elapsed time since the start of the recovery phase, in microseconds so the
        // cubic curve still advances between ACKs on sub-millisecond-RTT links.
        let t = now.total_micros() - recovery_start.total_micros();
        if t < 0 {
            return;
        }

        // RFC 9438 §4.3: use cubic function to get suggested cwnd.
        // W_cubic(t) = C(t - K)^3 + w_max, evaluated at the current time t.
        let c_as_bytes = C * self.min_cwnd as f64;
        let w_cubic = c_as_bytes * (t as f64 / 1_000_000.0 - self.k).powi(3) + self.w_max as f64;

        // RFC 9438 §4.3: advance our reno-like suggested cwnd.
        // When cwnd exceeds prior cwnd, change α_cubic to match Reno's AIMD.
        let w_est = {
            let alpha = if self.w_est >= self.cwnd_prior as f64 {
                1.0
            } else {
                ALPHA_CUBIC
            };

            self.w_est += alpha * self.min_cwnd as f64 * segment as f64 / self.cwnd as f64;
            self.w_est
        };

        // RFC 9438 §4.3: use the suggested window that grows fastest.
        if w_cubic < w_est {
            self.cwnd = (w_est as usize).min(self.rwnd).max(self.min_cwnd);
            return;
        }

        // RFC 9438 §4.2: the congestion window target is W_cubic one RTT into the future.
        let w_cubic_target = {
            // srtt is in millis so floor at 1ms to ensure sub-ms RTTs don't ruin the lookahead.
            let srtt = (rtt.smoothed_rtt() as u64 * 1000).max(1000);

            let t_ahead = (t as f64 + srtt as f64) / 1_000_000.0;
            let raw = c_as_bytes * (t_ahead - self.k).powi(3) + self.w_max as f64;
            raw.min(1.5 * self.cwnd as f64) // clamp to avoid increasing faster than slow-start would
        };

        // TODO: clamps to 0 on small w_cubic_target (i.e. close to plateau)
        // add additional counter (linux `cwnd_cnt`?) to track "lost" bytes
        let increment = (w_cubic_target as usize).saturating_sub(self.cwnd) * segment / self.cwnd;
        self.cwnd = (self.cwnd + increment).min(self.rwnd).max(self.min_cwnd);
    }

    fn on_dup_ack(&mut self, _now: Instant, len: usize, _in_flight: usize) {
        if self.in_fast_recovery {
            self.cwnd = self
                .cwnd
                .saturating_add(len)
                .min(self.rwnd)
                .max(self.min_cwnd);
        }
    }

    fn post_transmit(&mut self, now: Instant, _len: usize) {
        self.absorb_idle(now);
    }

    fn on_loss(&mut self, now: Instant, in_flight: usize) {
        self.idle_start = None;
        // Only cut window size on first entrance to fast recovery.
        if !self.in_fast_recovery {
            // RFC 9438 §4.3: remember the cwnd at this congestion event so W_est can
            // detect when it has recovered and switch α_cubic to 1.
            self.cwnd_prior = self.cwnd;

            // TODO: Make this optional?
            // RFC recommends (SHOULD) disabling if only a single CUBIC flow is on a network.
            //
            // RFC 9483.4.7: Fast Convergence
            // If loss happened at a smaller cwnd than before, it indicates a new flow.
            // Reduce the cubic plateau more than usual to create headroom.
            self.w_max = if self.cwnd < self.w_max {
                ((self.cwnd as f64) * (1.0 + BETA_CUBIC) / 2.0) as usize
            } else {
                self.cwnd
            };

            self.ssthresh = ((in_flight as f64 * BETA_CUBIC) as usize).max(2 * self.min_cwnd);
            self.cwnd = self
                .ssthresh
                .min(self.rwnd)
                .saturating_add(3 * self.min_cwnd);

            self.recovery_start = Some(now);
            self.in_fast_recovery = true;
            self.recompute_k();
        }
    }

    fn on_rto(&mut self, _now: Instant, in_flight: usize) {
        self.ssthresh = ((in_flight as f64 * BETA_CUBIC) as usize).max(2 * self.min_cwnd);
        self.cwnd = self.min_cwnd;
        self.cwnd_prior = in_flight;

        // RFC 9438 §4.8: defer W_max and K reset to the start of the next CA stage.
        self.recovery_start = None;
        self.in_fast_recovery = false;
        self.idle_start = None;
    }

    fn set_mss(&mut self, mss: usize) {
        self.min_cwnd = mss;
        self.recompute_k();
    }

    fn set_remote_window(&mut self, remote_window: usize) {
        if self.rwnd < remote_window {
            self.rwnd = remote_window;
        }
    }
}

#[inline]
fn abs(a: f64) -> f64 {
    if a < 0.0 { -a } else { a }
}

/// Calculate cube root by using the Newton-Raphson method.
fn cube_root(a: f64) -> Option<f64> {
    if a <= 0.0 {
        return None;
    }

    let (tolerance, init) = if a < 1_000.0 {
        (1.0, 8.879040017426005) // cube_root(700.0)
    } else if a < 1_000_000.0 {
        (5.0, 88.79040017426004) // cube_root(700_000.0)
    } else if a < 1_000_000_000.0 {
        (50.0, 887.9040017426004) // cube_root(700_000_000.0)
    } else if a < 1_000_000_000_000.0 {
        (500.0, 8879.040017426003) // cube_root(700_000_000_000.0)
    } else if a < 1_000_000_000_000_000.0 {
        (5000.0, 88790.40017426001) // cube_root(700_000_000_000.0)
    } else {
        (50000.0, 887904.0017426) // cube_root(700_000_000_000_000.0)
    };

    let mut x = init; // initial value
    let mut n = 20; // The maximum iteration
    loop {
        let next_x = (2.0 * x + a / (x * x)) / 3.0;
        if abs(next_x - x) < tolerance {
            return Some(next_x);
        }
        x = next_x;

        if n == 0 {
            return Some(next_x);
        }

        n -= 1;
    }
}

#[cfg(test)]
mod test {
    use crate::{socket::tcp::RttEstimator, time::Instant};

    use super::*;

    #[test]
    fn test_cubic() {
        let remote_window = 64 * 1024 * 1024;
        let now = Instant::from_millis(0);

        for i in 0..10 {
            for j in 0..9 {
                let mut cubic = Cubic::new();
                // Set remote window.
                cubic.set_remote_window(remote_window);

                cubic.set_mss(1480);

                if i & 1 == 0 {
                    cubic.on_rto(now, cubic.window());
                } else {
                    cubic.on_dup_ack(now, 1480, cubic.window());
                }

                cubic.pre_transmit(now);

                let mut n = i;
                for _ in 0..j {
                    n *= i;
                }

                let elapsed = Instant::from_millis(n);
                cubic.pre_transmit(elapsed);

                let cwnd = cubic.window();
                println!("Cubic: elapsed = {}, cwnd = {}", elapsed, cwnd);

                assert!(cwnd >= cubic.min_cwnd);
                assert!(cubic.window() <= remote_window);
            }
        }
    }

    #[test]
    fn cubic_time_inversion() {
        let mut cubic = Cubic::new();

        let t1 = Instant::from_micros(0);
        let t2 = Instant::from_micros(i64::MAX);

        cubic.on_rto(t2, cubic.window());
        cubic.pre_transmit(t1);

        let cwnd = cubic.window();
        println!("Cubic:time_inversion: cwnd: {}, cubic: {cubic:?}", cwnd);

        assert!(cwnd >= cubic.min_cwnd);
        assert!(cwnd <= cubic.rwnd);
    }

    #[test]
    fn cubic_long_elapsed_time() {
        let mut cubic = Cubic::new();

        let t1 = Instant::from_millis(0);
        let t2 = Instant::from_micros(i64::MAX);

        cubic.on_rto(t1, cubic.window());
        cubic.pre_transmit(t2);

        let cwnd = cubic.window();
        println!("Cubic:long_elapsed_time: cwnd: {}", cwnd);

        assert!(cwnd >= cubic.min_cwnd);
        assert!(cwnd <= cubic.rwnd);
    }

    #[test]
    fn cubic_last_update() {
        let mut cubic = Cubic::new();

        let t1 = Instant::from_millis(0);
        let t2 = Instant::from_millis(100);
        let t3 = Instant::from_millis(199);
        let t4 = Instant::from_millis(20000);

        cubic.on_rto(t1, cubic.window());

        cubic.pre_transmit(t2);
        let cwnd2 = cubic.window();

        cubic.pre_transmit(t3);
        let cwnd3 = cubic.window();

        cubic.pre_transmit(t4);
        let cwnd4 = cubic.window();

        println!(
            "Cubic:last_update: cwnd2: {}, cwnd3: {}, cwnd4: {}",
            cwnd2, cwnd3, cwnd4
        );

        assert_eq!(cwnd2, cwnd3);
        assert_ne!(cwnd2, cwnd4);
    }

    #[test]
    fn cubic_slow_start() {
        let mut cubic = Cubic::new();

        let t1 = Instant::from_micros(0);

        let cwnd = cubic.window();
        let ack_len = 1024;

        cubic.on_ack(t1, ack_len, cubic.window(), &RttEstimator::default());

        assert!(cubic.window() > cwnd);

        for i in 1..1000 {
            let t2 = Instant::from_micros(i);
            cubic.on_ack(t2, ack_len * 100, cubic.window(), &RttEstimator::default());
            assert!(cubic.window() <= cubic.rwnd);
        }

        let t3 = Instant::from_micros(2000);

        let cwnd = cubic.window();
        cubic.on_rto(t3, cubic.window());
        assert_eq!(cwnd >> 1, cubic.ssthresh);
    }

    #[test]
    fn cubic_pre_transmit() {
        let mut cubic = Cubic::new();
        cubic.pre_transmit(Instant::from_micros(2000));
    }

    #[test]
    fn test_cube_root() {
        for n in (1..1000000).step_by(99) {
            let a = n as f64;
            let a = a * a * a;
            let result = cube_root(a);
            println!("cube_root({a}) = {}", result.unwrap());
        }
    }

    #[test]
    #[should_panic]
    fn cube_root_zero() {
        cube_root(0.0).unwrap();
    }
}
