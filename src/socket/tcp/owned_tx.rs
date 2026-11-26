//! Immutable payloads occupying logical ranges of the normal retransmit ring.
//! Gaps hold ordinary copied sends. ACK retirement advances both representations.
use super::SocketBuffer;
use alloc::{collections::VecDeque, vec::Vec};

#[derive(Debug)]
struct Record {
    gap: usize,
    bytes: Vec<u8>,
    offset: usize,
    release: fn(&mut [u8]),
}

impl Drop for Record {
    fn drop(&mut self) {
        (self.release)(&mut self.bytes);
    }
}

#[derive(Debug, Default)]
pub(super) struct Records {
    records: VecDeque<Record>,
    // End of the final owned range, relative to the first unacknowledged byte.
    span: usize,
}

impl Records {
    pub(super) fn reserve(&mut self) -> bool {
        self.records.len() < 64 && self.records.try_reserve(1).is_ok()
    }

    pub(super) fn push(&mut self, queued: usize, bytes: Vec<u8>, release: fn(&mut [u8])) {
        let gap = queued - self.span;
        self.span = queued + bytes.len();
        self.records.push_back(Record {
            gap,
            bytes,
            offset: 0,
            release,
        });
    }

    pub(super) fn acknowledge(&mut self, len: usize) {
        let mut remaining = len.min(self.span);
        self.span -= remaining;
        while remaining > 0 {
            let record = self.records.front_mut().unwrap();
            let gap = record.gap.min(remaining);
            record.gap -= gap;
            remaining -= gap;
            let data = remaining.min(record.bytes.len() - record.offset);
            record.offset += data;
            remaining -= data;
            if record.offset == record.bytes.len() {
                self.records.pop_front();
            }
        }
    }

    pub(super) fn payload<'a>(
        &'a self,
        ring: &'a SocketBuffer<'_>,
        offset: usize,
        len: usize,
    ) -> &'a [u8] {
        let mut relative = offset;
        if offset < self.span {
            for record in &self.records {
                if relative < record.gap {
                    return ring.get_allocated(offset, len.min(record.gap - relative));
                }
                relative -= record.gap;
                let available = record.bytes.len() - record.offset;
                if relative < available {
                    let start = record.offset + relative;
                    return &record.bytes[start..start + len.min(available - relative)];
                }
                relative -= available;
            }
        }
        ring.get_allocated(offset, len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn mixed_sends_survive_wrap_partial_acks_and_retransmission() {
        static RELEASED: AtomicUsize = AtomicUsize::new(0);
        fn release(bytes: &mut [u8]) {
            bytes.fill(0);
            RELEASED.fetch_add(1, Ordering::Relaxed);
        }
        let mut ring = SocketBuffer::new(vec![0xee; 16]);
        let mut records = Records::default();
        ring.enqueue_slice(b"123456789");
        ring.dequeue_allocated(8);
        ring.enqueue_unallocated(4);
        records.push(1, b"abcd".to_vec(), release);
        ring.enqueue_slice(b"XYZ");
        ring.enqueue_unallocated(3);
        records.push(8, b"uvw".to_vec(), release);
        ring.enqueue_slice(b"00");
        let mut expected: &[u8] = b"9abcdXYZuvw00";
        for ack in [2, 2, 3, 2, 4] {
            // Inspect arbitrary retransmit offsets, including ring wrap, twice.
            for offset in (0..expected.len()).rev() {
                for n in [1, 3, 16] {
                    let data = records.payload(&ring, offset, n);
                    assert!(!data.is_empty());
                    assert!(data.len() <= n);
                    assert_eq!(data, &expected[offset..offset + data.len()]);
                }
            }
            records.acknowledge(ack);
            ring.dequeue_allocated(ack);
            expected = &expected[ack..];
        }
        assert_eq!(records.span, 0);
        assert_eq!(RELEASED.load(Ordering::Relaxed), 2);
        records.push(0, b"unsent".to_vec(), release);
        drop(records);
        assert_eq!(RELEASED.load(Ordering::Relaxed), 3);
    }
}
