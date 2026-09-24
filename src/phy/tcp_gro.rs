//! Checked, borrowed IPv4/TCP receive aggregation. This object changes storage
//! representation only; Ethernet/IP address admission stays in the interface.
use super::ChecksumCapabilities;
use crate::wire::{IpAddress, Ipv4Packet, TcpControl, TcpPacket};

pub use super::TCP_RX_MAX_FRAGMENTS as TCP_GRO_MAX_SEGMENTS;
const TCP: usize = 34;
/// Includes the Ethernet header. 48 KiB fits 32 MTU-1500 data segments
/// while remaining below the IPv4 length limit, including fallback emission.
#[cfg(feature = "tcp-gro-full-batch")]
pub const TCP_GRO_MAX_BYTES: usize = 48 * 1024;
#[cfg(not(feature = "tcp-gro-full-batch"))]
pub const TCP_GRO_MAX_BYTES: usize = 32 * 1024;
fn u16_at(b: &[u8], n: usize) -> u16 { u16::from_be_bytes([b[n], b[n + 1]]) }
fn sequence(b: &[u8]) -> u32 { u32::from_be_bytes(b[38..42].try_into().unwrap()) }

fn eligible(b: &[u8], caps: &ChecksumCapabilities) -> Option<(usize, usize)> {
    if b.len() < 54 || b[12..14] != [8, 0] || b[14] != 0x45
        || b[23] != 6 || b[15] & 3 != 0 || u16_at(b, 20) != 0x4000 {
        return None;
    }
    let end = 14 + u16_at(b, 16) as usize;
    let header = TCP + (b[46] >> 4) as usize * 4;
    if end > b.len() || header < 54 || header >= end || b[46] & 15 != 0
        || !matches!(b[47], 0x10 | 0x18) || u16_at(b, 52) != 0 { return None; }
    if header != 54 && !(header == 66 && b[54..58] == [1, 1, 8, 10]) { return None; }
    let ip = Ipv4Packet::new_checked(&b[14..end]).ok()?;
    let tcp = TcpPacket::new_checked(&b[TCP..end]).ok()?;
    if caps.ipv4.rx() && !ip.verify_checksum() { return None; }
    if caps.tcp.rx() && !tcp.verify_checksum(&IpAddress::from(ip.src_addr()), &IpAddress::from(ip.dst_addr())) { return None; }
    Some((header, end))
}

/// A validated group of a bounded number of same-flow data frames, borrowed synchronously.
/// Atomic IPv4 IDs are not significant (DF=1, MF=0, offset=0). All other GRO
/// compatibility checks, including each original checksum policy, apply before
/// this object can be constructed. Incoming bytes are neither changed nor
/// copied; every view remains tied to the original immutable borrow.
pub struct TcpGro<'a> {
    first: &'a [u8],
    payloads: [&'a [u8]; TCP_GRO_MAX_SEGMENTS],
    count: usize,
    header: usize,
    length: usize,
    flags: u8,
    verified_ipv4: bool,
    verified_tcp: bool,
}

/// A synchronous receive result. `Group` carries immutable validated data,
/// while ordinary frames retain the interface's normal parsing path.
pub enum TcpGroRx<'a> {
    Frame(&'a [u8]),
    Group(TcpGro<'a>),
    Invalid,
}

/// Why a frame cannot follow the currently accepted GRO prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpGroReject {
    /// PSH or a short segment already terminated this prefix.
    Finished,
    /// The bounded segment count or total byte limit would be exceeded.
    Capacity,
    /// The incoming frame is malformed, unsupported, or fails checksum policy.
    Ineligible,
    /// Flow/header metadata or the next TCP sequence does not match.
    Incompatible,
}

/// Incrementally validate one borrowed receive group without a second pass.
///
/// The checksum policy is captured at construction. Every appended frame is
/// borrowed immutably until the resulting group is consumed. Rejection leaves
/// the accepted prefix unchanged; the caller retains the rejected frame for
/// normal single-frame processing or the next group. No payload is copied.
/// A one-frame prefix is not an aggregate and `finish` returns `None` for it.
///
/// The original storage cannot be changed while its validation is retained:
///
/// ```compile_fail
/// use smoltcp::phy::{ChecksumCapabilities, TcpGroBuilder};
/// let mut bytes = [0u8; 64];
/// let builder = TcpGroBuilder::new(&bytes, &ChecksumCapabilities::default()).unwrap();
/// bytes[0] = 1;
/// let _ = builder.finish();
/// ```
pub struct TcpGroBuilder<'a> {
    group: TcpGro<'a>,
    caps: ChecksumCapabilities,
    mss: usize,
    next_sequence: u32,
    finished: bool,
}

impl<'a> TcpGroBuilder<'a> {
    pub fn new(first: &'a [u8], caps: &ChecksumCapabilities) -> Option<Self> {
        let (header, end) = eligible(first, caps)?;
        if end > TCP_GRO_MAX_BYTES { return None; }
        let mss = end - header;
        let mut payloads = [&[][..]; TCP_GRO_MAX_SEGMENTS];
        payloads[0] = &first[header..end];
        Some(Self {
            group: TcpGro { first, payloads, count: 1, header, length: mss, flags: first[47],
                verified_ipv4: caps.ipv4.rx(), verified_tcp: caps.tcp.rx() },
            caps: caps.clone(), mss,
            next_sequence: sequence(first).wrapping_add(mss as u32),
            finished: first[47] & 8 != 0,
        })
    }

    pub fn push(&mut self, frame: &'a [u8]) -> Result<(), TcpGroReject> {
        if self.finished { return Err(TcpGroReject::Finished); }
        if self.group.count == TCP_GRO_MAX_SEGMENTS { return Err(TcpGroReject::Capacity); }
        let (header, end) = eligible(frame, &self.caps).ok_or(TcpGroReject::Ineligible)?;
        let size = end - header;
        let first = self.group.first;
        if header != self.group.header || size > self.mss || sequence(frame) != self.next_sequence
            || frame[..16] != first[..16] || frame[20..24] != first[20..24]
            || frame[26..38] != first[26..38] || frame[42..47] != first[42..47]
            || frame[48..50] != first[48..50] || frame[54..header] != first[54..header] {
            return Err(TcpGroReject::Incompatible);
        }
        let length = self.group.length.checked_add(size).ok_or(TcpGroReject::Capacity)?;
        if header + length > TCP_GRO_MAX_BYTES { return Err(TcpGroReject::Capacity); }
        // Commit only after every check: callers can retry a different frame
        // or finish the previously accepted prefix after any rejection.
        self.group.payloads[self.group.count] = &frame[header..end];
        self.group.count += 1;
        self.group.length = length;
        self.group.flags = frame[47];
        self.next_sequence = self.next_sequence.wrapping_add(size as u32);
        self.finished = frame[47] & 8 != 0 || size < self.mss;
        Ok(())
    }

    pub fn segment_count(&self) -> usize { self.group.count }
    pub fn is_finished(&self) -> bool { self.finished || self.group.count == TCP_GRO_MAX_SEGMENTS }
    pub fn finish(self) -> Option<TcpGro<'a>> {
        (self.group.count >= 2).then_some(self.group)
    }
}

impl<'a> TcpGro<'a> {
    /// Whether this immutable group was checked at least as strongly as the
    /// consumer requires. A device cannot weaken Interface checksum policy by
    /// passing a group constructed with offload/ignored checksums.
    pub fn satisfies_checksum_policy(&self, caps: &ChecksumCapabilities) -> bool {
        (!caps.ipv4.rx() || self.verified_ipv4) && (!caps.tcp.rx() || self.verified_tcp)
    }
    pub fn first_frame(&self) -> &'a [u8] { self.first }
    pub fn new(frames: &[&'a [u8]], caps: &ChecksumCapabilities) -> Option<Self> {
        if frames.len() < 2 || frames.len() > TCP_GRO_MAX_SEGMENTS { return None; }
        let mut builder = TcpGroBuilder::new(frames[0], caps)?;
        for frame in &frames[1..] { builder.push(frame).ok()?; }
        builder.finish()
    }
    pub fn payloads(&self) -> &[&'a [u8]] { &self.payloads[..self.count] }
    pub fn ip_payload_len(&self) -> usize { self.header - TCP + self.length }
    pub fn control(&self) -> TcpControl {
        if self.flags & 8 != 0 { TcpControl::Psh } else { TcpControl::None }
    }
    /// Bounded fallback for consumers (notably raw sockets) that need one slice.
    pub fn materialize(&self) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec::Vec::with_capacity(self.header + self.length);
        bytes.extend_from_slice(&self.first[..self.header]);
        for payload in self.payloads() { bytes.extend_from_slice(payload); }
        bytes[16..18].copy_from_slice(&((self.header + self.length - 14) as u16).to_be_bytes());
        bytes[47] = self.flags;
        let mut ip = Ipv4Packet::new_unchecked(&mut bytes[14..]);
        ip.fill_checksum();
        let (src, dst) = (IpAddress::from(ip.src_addr()), IpAddress::from(ip.dst_addr()));
        TcpPacket::new_unchecked(&mut bytes[TCP..]).fill_checksum(&src, &dst);
        bytes
    }
}
