//! A bounded, in-memory journal of recent patches, so a peer that
//! reconnects after missing only a few changes can be caught up with a
//! small incremental patch instead of a full vault resync.
//!
//! This is deliberately **in-memory only, scoped to one `serve` run** --
//! not persisted to disk. That's a conscious simplification, not an
//! oversight: persisting it durably would mean either writing it inside
//! the `.rvlt` file (another format change, and more bytes rewritten per
//! mutation for a feature that's a pure efficiency optimization) or a
//! separate on-disk cache file (which works, and would be the natural
//! next step, but adds a file-format and crash-consistency surface of
//! its own). Losing the journal (e.g. the admin restarts `serve`) simply
//! means falling back to a full resync for whoever reconnects after
//! that -- always correct, just not maximally efficient. See
//! `docs/ARCHITECTURE_NETWORK.md`.

use std::collections::VecDeque;

pub struct PatchJournal {
    /// Ordered, contiguous by `seq` (each push is the next seq after the
    /// previous one) -- oldest at the front.
    entries: VecDeque<(u64, Vec<(u64, Vec<u8>)>)>,
    capacity: usize,
}

impl PatchJournal {
    pub fn new(capacity: usize) -> Self {
        PatchJournal { entries: VecDeque::with_capacity(capacity), capacity }
    }

    /// Records the patch produced by the mutation that advanced the
    /// chain to `seq`. Call this right after `Vault::take_change_log`.
    pub fn record(&mut self, seq: u64, ranges: Vec<(u64, Vec<u8>)>) {
        if self.capacity == 0 {
            return;
        }
        self.entries.push_back((seq, ranges));
        while self.entries.len() > self.capacity {
            self.entries.pop_front();
        }
    }

    /// If the journal has unbroken coverage of every change since
    /// `peer_next_seq` (i.e. nothing has fallen off the front past what
    /// the peer still needs), returns the combined, in-order ranges to
    /// bring them up to date. Returns `None` if the peer is further
    /// behind than the journal's retained window -- the caller should
    /// fall back to a full resync in that case.
    pub fn ranges_since(&self, peer_next_seq: u64) -> Option<Vec<(u64, Vec<u8>)>> {
        if peer_next_seq == 0 {
            // A peer with no local replica at all always needs a full
            // sync, never a patch (patches assume a byte-identical
            // starting replica to apply ranges onto).
            return None;
        }
        let Some(&(oldest_seq, _)) = self.entries.front() else {
            // Empty journal: can't prove coverage of anything.
            return None;
        };
        if peer_next_seq < oldest_seq {
            // The peer needs history that has already rolled off the
            // front of the journal -- no coverage.
            return None;
        }
        let mut combined = Vec::new();
        for (seq, ranges) in &self.entries {
            if *seq >= peer_next_seq {
                combined.extend(ranges.iter().cloned());
            }
        }
        Some(combined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_journal_never_claims_coverage() {
        let j = PatchJournal::new(4);
        assert!(j.ranges_since(1).is_none());
    }

    #[test]
    fn returns_combined_ranges_when_fully_covered() {
        let mut j = PatchJournal::new(4);
        j.record(1, vec![(0, vec![1, 2])]);
        j.record(2, vec![(100, vec![3, 4])]);
        j.record(3, vec![(200, vec![5, 6])]);

        // Peer is at seq 1 (i.e. next_seq == 1, meaning they have
        // everything up through seq 0) -- needs records 1, 2, and 3.
        let combined = j.ranges_since(1).unwrap();
        assert_eq!(combined, vec![(0, vec![1, 2]), (100, vec![3, 4]), (200, vec![5, 6])]);

        // Peer already has seq 1 applied (next_seq == 2) -- needs 2 and 3 only.
        let combined = j.ranges_since(2).unwrap();
        assert_eq!(combined, vec![(100, vec![3, 4]), (200, vec![5, 6])]);
    }

    #[test]
    fn falls_back_to_none_once_history_rolls_off() {
        let mut j = PatchJournal::new(2);
        j.record(1, vec![(0, vec![1])]);
        j.record(2, vec![(1, vec![2])]);
        j.record(3, vec![(2, vec![3])]); // seq 1 now evicted (capacity 2)

        // Peer needs seq 1 onward, but we no longer have it.
        assert!(j.ranges_since(1).is_none());
        // Peer needs seq 2 onward -- still covered.
        assert!(j.ranges_since(2).is_some());
    }

    #[test]
    fn brand_new_peer_always_gets_none_even_if_covered() {
        let mut j = PatchJournal::new(4);
        j.record(1, vec![(0, vec![1])]);
        assert!(j.ranges_since(0).is_none());
    }

    #[test]
    fn zero_capacity_journal_never_covers_anything() {
        let mut j = PatchJournal::new(0);
        j.record(1, vec![(0, vec![1])]);
        assert!(j.ranges_since(1).is_none());
    }
}
