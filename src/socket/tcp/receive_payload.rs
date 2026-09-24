//! Borrowed receive data for a single TCP state-machine invocation.
//! Slicing clips the logical stream; scatter writes copy directly into the
//! socket ring without materializing an intermediate aggregate.
use core::ops::Range;
use super::SocketBuffer;

pub(super) trait ReceivePayload: Copy {
    fn len(self) -> usize;
    fn is_empty(self) -> bool { self.len() == 0 }
    fn slice(self, range: Range<usize>) -> Self;
    fn write_into(self, ring: &mut SocketBuffer<'_>, offset: usize) -> usize;
    #[cfg(feature = "tcp-align-empty-rx")]
    fn first_alignment(self) -> Option<usize>;
}

impl ReceivePayload for &[u8] {
    #[cfg(feature = "tcp-align-empty-rx")]
    fn first_alignment(self) -> Option<usize> {
        (!self.is_empty()).then(|| self.as_ptr() as usize & (core::mem::align_of::<usize>() - 1))
    }
    #[inline]
    fn len(self) -> usize { <[u8]>::len(self) }
    #[inline]
    fn slice(self, range: Range<usize>) -> Self { &self[range] }
    #[inline]
    fn write_into(self, ring: &mut SocketBuffer<'_>, offset: usize) -> usize {
        ring.write_unallocated(offset, self)
    }
}

#[cfg(feature = "tcp-scatter-receive")]
#[derive(Clone, Copy)]
pub(super) struct Scattered<'a> {
    fragments: &'a [&'a [u8]],
    start: usize,
    length: usize,
}

#[cfg(feature = "tcp-scatter-receive")]
impl<'a> Scattered<'a> {
    pub(super) fn new(fragments: &'a [&'a [u8]]) -> Option<Self> {
        // Match the bounded GRO ingress contract and prevent pathological
        // fragment iteration or sequence-length overflow at this boundary.
        if fragments.len() > crate::phy::TCP_RX_MAX_FRAGMENTS { return None; }
        let length = fragments.iter().try_fold(0usize, |n, f| n.checked_add(f.len()))?;
        if length > 65535 { return None; }
        Some(Self { fragments, start: 0, length })
    }
}

#[cfg(feature = "tcp-scatter-receive")]
impl ReceivePayload for Scattered<'_> {
    #[cfg(feature = "tcp-align-empty-rx")]
    fn first_alignment(self) -> Option<usize> {
        if self.length == 0 { return None; }
        let mut skip = self.start;
        for fragment in self.fragments {
            if skip < fragment.len() {
                return Some(fragment[skip..].as_ptr() as usize & (core::mem::align_of::<usize>() - 1));
            }
            skip -= fragment.len();
        }
        None
    }
    fn len(self) -> usize { self.length }
    fn slice(self, range: Range<usize>) -> Self {
        assert!(range.start <= range.end && range.end <= self.length);
        Self { start: self.start + range.start, length: range.end - range.start, ..self }
    }
    fn write_into(self, ring: &mut SocketBuffer<'_>, offset: usize) -> usize {
        let length = self.length.min(ring.window().saturating_sub(offset));
        if length == 0 { return 0; }
        let mut skip = self.start;
        let mut index = 0;
        while skip >= self.fragments[index].len() {
            skip -= self.fragments[index].len();
            index += 1;
        }
        let mut written = 0;
        // A clipped logical receive range spans at most two contiguous ring
        // regions. Compute their indices once each, rather than recomputing
        // two ring positions (and issuing an empty copy) for every fragment.
        while written < length {
            let output = ring.get_unallocated(offset + written, length - written);
            debug_assert!(!output.is_empty());
            let mut filled = 0;
            while filled < output.len() {
                let fragment = self.fragments[index];
                let count = (fragment.len() - skip).min(output.len() - filled);
                output[filled..filled + count].copy_from_slice(&fragment[skip..skip + count]);
                filled += count;
                skip += count;
                if skip == fragment.len() { index += 1; skip = 0; }
            }
            written += filled;
        }
        written
    }
}

#[cfg(all(test, feature = "tcp-scatter-receive"))]
mod tests {
    use super::*;

    #[test]
    fn batched_scatter_matches_contiguous_for_ring_positions_and_windows() {
        let bytes: [u8; 48] = core::array::from_fn(|n| (n * 7 + 3) as u8);
        let fragments: [&[u8]; 6] = [&[], &bytes[..7], &[], &bytes[7..31], &bytes[31..], &[]];
        for capacity in [0usize, 1, 5, 16, 32, 49] {
            for position in [0, capacity / 2, capacity.saturating_sub(1)] {
                for allocated in [0, capacity / 2, capacity] {
                    for offset in 0..=capacity + 1 {
                        for range in [0..0, 0..48, 1..7, 7..31, 6..32, 31..48, 48..48] {
                            let mut a = [0u8; 49];
                            let mut b = [0u8; 49];
                            let mut expected = SocketBuffer::new(&mut a[..capacity]);
                            let mut actual = SocketBuffer::new(&mut b[..capacity]);
                            for ring in [&mut expected, &mut actual] {
                                assert_eq!(ring.enqueue_slice(&[0x55; 49][..position]), position);
                                assert_eq!(ring.dequeue_slice(&mut [0u8; 49][..position]), position);
                                ring.get_unallocated(0, allocated).fill(0xa5);
                                ring.enqueue_unallocated(allocated);
                            }
                            let n = expected.write_unallocated(offset, &bytes[range.clone()]);
                            assert_eq!(Scattered::new(&fragments).unwrap().slice(range).write_into(&mut actual, offset), n);
                            assert_eq!(actual.len(), expected.len());
                            for ring in [&mut expected, &mut actual] { ring.enqueue_unallocated(ring.window()); }
                            let mut x = [0; 49]; let mut y = [0; 49];
                            assert_eq!(expected.dequeue_slice(&mut x), actual.dequeue_slice(&mut y));
                            assert_eq!(x, y);
                        }
                    }
                }
            }
        }
    }

    #[test]
    #[cfg(feature = "tcp-align-empty-rx")]
    fn alignment_uses_first_nonempty_clipped_fragment() {
        let source = [0u8; 48];
        let fragments = [&source[..0], &source[..7], &source[7..7], &source[7..31], &source[31..], &source[48..]];
        let mask = core::mem::align_of::<usize>() - 1;
        for start in 0..=48 {
            for end in start..=48 {
                let view = Scattered::new(&fragments).unwrap().slice(start..end);
                assert_eq!(view.first_alignment(), if start == end { None } else { Some(source[start..].as_ptr() as usize & mask) });
            }
        }
    }

    #[test]
    fn sixteen_fragments_clip_and_short_write_across_ring_wrap() {
        let source: [u8; 48] = core::array::from_fn(|n| (n * 11 + 7) as u8);
        let fragments: [&[u8]; 16] = core::array::from_fn(|n| &source[n * 3..n * 3 + 3]);
        for start in 0..=source.len() {
            for end in start..=source.len() {
                let mut storage = [0; 32];
                let mut ring = SocketBuffer::new(&mut storage[..]);
                assert_eq!(ring.enqueue_slice(&[0; 24]), 24);
                assert_eq!(ring.dequeue_slice(&mut [0; 24]), 24);
                let view = Scattered::new(&fragments).unwrap().slice(start..end);
                let written = view.write_into(&mut ring, 5);
                assert_eq!(written, (end - start).min(27));
                ring.enqueue_unallocated(5 + written);
                let mut output = [0; 32];
                assert_eq!(ring.dequeue_slice(&mut output), 5 + written);
                assert_eq!(&output[5..5 + written], &source[start..start + written]);
            }
        }
    }
}
