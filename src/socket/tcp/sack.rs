//! NOTE(zfc): sender-side SACK scoreboard (RFC 2018 / RFC 6675, simplified).
//!
//! Records which ranges above `snd_una` the peer has reported as received
//! out of order, so that loss recovery can retransmit only the holes and so
//! that SACKed bytes stop counting against the congestion window. Without it a
//! window with several losses is repaired one hole per RTT (or by RTO), which
//! is what collapsed WG-inbound downloads on lossy / shallow-buffer paths (#637).

use crate::wire::TcpSeqNumber;

/// Maximum number of disjoint SACKed ranges tracked. When full, a new range that
/// cannot be merged is dropped: under-reporting SACKed data only makes recovery
/// more conservative (it retransmits more), never incorrect.
const MAX_RANGES: usize = 16;

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(super) struct SackBoard {
    /// Disjoint, non-adjacent `[start, end)` ranges, sorted by `start`.
    ranges: [(TcpSeqNumber, TcpSeqNumber); MAX_RANGES],
    len: usize,
}

impl Default for SackBoard {
    fn default() -> Self {
        SackBoard {
            ranges: [(TcpSeqNumber::default(), TcpSeqNumber::default()); MAX_RANGES],
            len: 0,
        }
    }
}

impl SackBoard {
    pub(super) fn clear(&mut self) {
        self.len = 0;
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn slice(&self) -> &[(TcpSeqNumber, TcpSeqNumber)] {
        &self.ranges[..self.len]
    }

    /// Record `[start, end)` as SACKed, merging with overlapping/adjacent ranges.
    pub(super) fn add(&mut self, start: TcpSeqNumber, end: TcpSeqNumber) {
        if end <= start {
            return;
        }
        let (mut start, mut end) = (start, end);
        // Collect the ranges that do not touch the new one, merging the rest in.
        let mut kept = [(TcpSeqNumber::default(), TcpSeqNumber::default()); MAX_RANGES];
        let mut kept_len = 0;
        for &(s, e) in self.slice() {
            if e < start || s > end {
                kept[kept_len] = (s, e);
                kept_len += 1;
            } else {
                start = start.min(s);
                end = end.max(e);
            }
        }
        if kept_len == MAX_RANGES {
            return;
        }
        // Insert keeping the order by start.
        let pos = kept[..kept_len]
            .iter()
            .position(|&(s, _)| s > start)
            .unwrap_or(kept_len);
        let mut i = kept_len;
        while i > pos {
            kept[i] = kept[i - 1];
            i -= 1;
        }
        kept[pos] = (start, end);
        self.ranges = kept;
        self.len = kept_len + 1;
    }

    /// Forget everything below `snd_una` (it has been cumulatively ACKed).
    pub(super) fn prune(&mut self, snd_una: TcpSeqNumber) {
        let mut out = 0;
        for i in 0..self.len {
            let (s, e) = self.ranges[i];
            if e <= snd_una {
                continue;
            }
            self.ranges[out] = (s.max(snd_una), e);
            out += 1;
        }
        self.len = out;
    }

    /// Total SACKed octets.
    pub(super) fn sacked_bytes(&self) -> usize {
        self.slice().iter().map(|&(s, e)| e - s).sum()
    }

    /// SACKed octets within `[from, to)`.
    pub(super) fn sacked_in(&self, from: TcpSeqNumber, to: TcpSeqNumber) -> usize {
        if to <= from {
            return 0;
        }
        self.slice()
            .iter()
            .map(|&(s, e)| {
                let (s, e) = (s.max(from), e.min(to));
                if e > s { e - s } else { 0 }
            })
            .sum()
    }

    /// Highest SACKed sequence number (exclusive end), if any.
    pub(super) fn highest(&self) -> Option<TcpSeqNumber> {
        self.slice().last().map(|&(_, e)| e)
    }

    /// First un-SACKed hole `[a, b)` with `from <= a < limit`; `b` is capped at
    /// `limit` and at the start of the next SACKed range.
    pub(super) fn next_hole(
        &self,
        from: TcpSeqNumber,
        limit: TcpSeqNumber,
    ) -> Option<(TcpSeqNumber, TcpSeqNumber)> {
        let mut a = from;
        for &(s, e) in self.slice() {
            if e <= a {
                continue;
            }
            if s <= a {
                // `a` is inside a SACKed range: skip past it.
                a = e;
                continue;
            }
            // Gap [a, s) before this range.
            if a >= limit {
                return None;
            }
            return Some((a, s.min(limit)));
        }
        if a < limit { Some((a, limit)) } else { None }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn seq(n: i32) -> TcpSeqNumber {
        TcpSeqNumber(n)
    }

    #[test]
    fn add_merges_and_orders() {
        let mut b = SackBoard::default();
        b.add(seq(30), seq(40));
        b.add(seq(10), seq(20));
        b.add(seq(20), seq(25)); // adjacent to [10,20)
        assert_eq!(b.slice(), &[(seq(10), seq(25)), (seq(30), seq(40))]);
        b.add(seq(24), seq(31)); // bridges both
        assert_eq!(b.slice(), &[(seq(10), seq(40))]);
        assert_eq!(b.sacked_bytes(), 30);
        assert_eq!(b.highest(), Some(seq(40)));
    }

    #[test]
    fn prune_trims_below_snd_una() {
        let mut b = SackBoard::default();
        b.add(seq(10), seq(20));
        b.add(seq(30), seq(40));
        b.prune(seq(15));
        assert_eq!(b.slice(), &[(seq(15), seq(20)), (seq(30), seq(40))]);
        b.prune(seq(35));
        assert_eq!(b.slice(), &[(seq(35), seq(40))]);
        b.prune(seq(40));
        assert!(b.is_empty());
    }

    #[test]
    fn next_hole_walks_gaps() {
        let mut b = SackBoard::default();
        b.add(seq(10), seq(20));
        b.add(seq(30), seq(40));
        // holes below highest SACK: [0,10) and [20,30)
        assert_eq!(b.next_hole(seq(0), seq(40)), Some((seq(0), seq(10))));
        assert_eq!(b.next_hole(seq(10), seq(40)), Some((seq(20), seq(30))));
        assert_eq!(b.next_hole(seq(25), seq(40)), Some((seq(25), seq(30))));
        assert_eq!(b.next_hole(seq(30), seq(40)), None);
        // after RTO everything un-SACKed up to the send frontier is lost
        assert_eq!(b.next_hole(seq(30), seq(50)), Some((seq(40), seq(50))));
    }

    #[test]
    fn sacked_in_clips_to_window() {
        let mut b = SackBoard::default();
        b.add(seq(10), seq(20));
        b.add(seq(30), seq(40));
        assert_eq!(b.sacked_in(seq(0), seq(100)), 20);
        assert_eq!(b.sacked_in(seq(15), seq(35)), 10);
        assert_eq!(b.sacked_in(seq(20), seq(30)), 0);
        assert_eq!(b.sacked_in(seq(35), seq(15)), 0);
    }

    #[test]
    fn full_board_drops_unmergeable_range() {
        let mut b = SackBoard::default();
        for i in 0..MAX_RANGES as i32 {
            b.add(seq(i * 10), seq(i * 10 + 5));
        }
        b.add(seq(1000), seq(1005));
        assert_eq!(b.len, MAX_RANGES);
        assert_eq!(b.highest(), Some(seq((MAX_RANGES as i32 - 1) * 10 + 5)));
        // A mergeable range is still accepted.
        b.add(seq(5), seq(10));
        assert_eq!(b.len, MAX_RANGES - 1);
    }
}
