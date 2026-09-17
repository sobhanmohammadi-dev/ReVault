//! Free/occupied block bitmap allocator.
//!
//! The bitmap is a plain array of bits (1 bit per block, MSB-first within
//! each byte), stored on-disk verbatim in the vault's bitmap region so it
//! survives reopening without needing to rescan the file table.

#[derive(Debug, Clone)]
pub struct BlockAllocator {
    bits: Vec<u8>,
    block_count: u64,
}

impl BlockAllocator {
    pub fn new(block_count: u64) -> Self {
        let byte_len = Self::bitmap_len_bytes(block_count);
        BlockAllocator { bits: vec![0u8; byte_len as usize], block_count }
    }

    pub fn from_bytes(bits: Vec<u8>, block_count: u64) -> Self {
        let mut bits = bits;
        let needed = Self::bitmap_len_bytes(block_count) as usize;
        bits.resize(needed, 0);
        BlockAllocator { bits, block_count }
    }

    pub fn bitmap_len_bytes(block_count: u64) -> u64 {
        block_count.div_ceil(8)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }

    pub fn is_free(&self, index: u64) -> bool {
        if index >= self.block_count {
            return false;
        }
        let byte = self.bits[(index / 8) as usize];
        (byte >> (index % 8)) & 1 == 0
    }

    fn set(&mut self, index: u64, occupied: bool) {
        let byte = &mut self.bits[(index / 8) as usize];
        let mask = 1u8 << (index % 8);
        if occupied {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }

    pub fn free_count(&self) -> u64 {
        self.block_count - (0..self.block_count).filter(|&i| !self.is_free(i)).count() as u64
    }

    pub fn occupied_count(&self) -> u64 {
        self.block_count - self.free_count()
    }

    /// Allocates up to `count` free blocks, marking them occupied.
    /// Returns fewer than `count` indices only if the pool is exhausted.
    pub fn allocate(&mut self, count: u64) -> Vec<u64> {
        let mut out = Vec::with_capacity(count as usize);
        for i in 0..self.block_count {
            if out.len() as u64 == count {
                break;
            }
            if self.is_free(i) {
                self.set(i, true);
                out.push(i);
            }
        }
        out
    }

    pub fn free(&mut self, indices: &[u64]) {
        for &i in indices {
            if i < self.block_count {
                self.set(i, false);
            }
        }
    }

    pub fn mark_occupied(&mut self, indices: &[u64]) {
        for &i in indices {
            if i < self.block_count {
                self.set(i, true);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_allocator_all_free() {
        let a = BlockAllocator::new(10);
        assert_eq!(a.free_count(), 10);
        assert_eq!(a.occupied_count(), 0);
    }

    #[test]
    fn allocate_marks_occupied_and_is_stable() {
        let mut a = BlockAllocator::new(4);
        let got = a.allocate(2);
        assert_eq!(got.len(), 2);
        assert_eq!(a.occupied_count(), 2);
        for idx in &got {
            assert!(!a.is_free(*idx));
        }
    }

    #[test]
    fn allocate_saturates_when_exhausted() {
        let mut a = BlockAllocator::new(2);
        let got = a.allocate(5);
        assert_eq!(got.len(), 2);
        assert_eq!(a.allocate(1).len(), 0);
    }

    #[test]
    fn free_returns_blocks_to_pool() {
        let mut a = BlockAllocator::new(4);
        let got = a.allocate(3);
        a.free(&got[..1]);
        assert_eq!(a.free_count(), 2);
        assert!(a.is_free(got[0]));
    }

    #[test]
    fn roundtrip_through_bytes() {
        let mut a = BlockAllocator::new(20);
        a.allocate(5);
        let bytes = a.as_bytes().to_vec();
        let b = BlockAllocator::from_bytes(bytes, 20);
        assert_eq!(a.occupied_count(), b.occupied_count());
        for i in 0..20 {
            assert_eq!(a.is_free(i), b.is_free(i));
        }
    }

    #[test]
    fn allocate_zero_returns_empty_and_changes_nothing() {
        let mut a = BlockAllocator::new(10);
        let got = a.allocate(0);
        assert!(got.is_empty());
        assert_eq!(a.free_count(), 10);
    }

    #[test]
    fn freeing_an_already_free_block_is_idempotent() {
        let mut a = BlockAllocator::new(4);
        a.free(&[2]); // never allocated -- already free
        assert_eq!(a.occupied_count(), 0);
        let got = a.allocate(1);
        a.free(&got);
        a.free(&got); // double free of the same block
        assert_eq!(a.occupied_count(), 0);
        assert_eq!(a.free_count(), 4);
    }

    #[test]
    fn mark_occupied_then_free_roundtrips() {
        let mut a = BlockAllocator::new(8);
        a.mark_occupied(&[0, 3, 5]);
        assert_eq!(a.occupied_count(), 3);
        assert!(!a.is_free(3));
        a.free(&[3]);
        assert_eq!(a.occupied_count(), 2);
        assert!(a.is_free(3));
    }
}
