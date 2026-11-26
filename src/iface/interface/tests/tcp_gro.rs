use super::*;
use crate::phy::{DeviceCapabilities, RxToken as RxTrait, TcpGro, TcpGroBuilder, TcpGroReject};
use crate::socket::tcp;

#[derive(Default)]
struct GroupDevice { frames: Option<Vec<Vec<u8>>>, sent: Vec<Vec<u8>> }
struct GroupRx(Vec<Vec<u8>>);
struct GroupTx<'a>(&'a mut Vec<Vec<u8>>);
impl RxTrait for GroupRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        if self.0.len() == 1 { return f(&self.0[0]); }
        let refs: Vec<&[u8]> = self.0.iter().map(Vec::as_slice).collect();
        f(&TcpGro::new(&refs, &ChecksumCapabilities::default()).unwrap().materialize())
    }
    fn consume_gro<R, F: FnOnce(&[&[u8]]) -> R>(self, f: F) -> R {
        let refs: Vec<&[u8]> = self.0.iter().map(Vec::as_slice).collect();
        f(&refs)
    }
}
impl TxToken for GroupTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut bytes = vec![0; len]; let result = f(&mut bytes); self.0.push(bytes); result
    }
}
impl Device for GroupDevice {
    type RxToken<'a> = GroupRx;
    type TxToken<'a> = GroupTx<'a>;
    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities { medium: Medium::Ethernet, max_transmission_unit: 1514, ..Default::default() }
    }
    fn receive(&mut self, _: Instant) -> Option<(GroupRx, GroupTx<'_>)> {
        Some((GroupRx(self.frames.take()?), GroupTx(&mut self.sent)))
    }
    fn transmit(&mut self, _: Instant) -> Option<GroupTx<'_>> { Some(GroupTx(&mut self.sent)) }
}
fn checksums(b: &mut [u8]) {
    let mut ip = Ipv4Packet::new_unchecked(&mut b[14..]); ip.fill_checksum();
    let (src, dst) = (ip.src_addr().into(), ip.dst_addr().into());
    TcpPacket::new_unchecked(&mut b[34..]).fill_checksum(&src, &dst);
}
fn frame(seq: i32, ack: Option<i32>, control: TcpControl, bytes: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 54 + bytes.len()];
    b[..12].copy_from_slice(&[2,2,2,2,2,2, 2,2,2,2,2,3]); b[12..14].copy_from_slice(&[8,0]);
    b[14] = 0x45; b[16..18].copy_from_slice(&((40+bytes.len()) as u16).to_be_bytes());
    b[20] = 0x40; b[22] = 64; b[23] = 6;
    b[26..34].copy_from_slice(&[192,168,1,2, 192,168,1,1]);
    let repr = TcpRepr { src_port: 1234, dst_port: 80, control, seq_number: TcpSeqNumber(seq),
        ack_number: ack.map(TcpSeqNumber), window_len: 4096, window_scale: None,
        max_seg_size: None, sack_permitted: false, sack_ranges: [None;3], timestamp: None, payload: bytes };
    repr.emit(&mut TcpPacket::new_unchecked(&mut b[34..]),
        &IpAddress::v4(192,168,1,2), &IpAddress::v4(192,168,1,1), &ChecksumCapabilities::default());
    checksums(&mut b); b
}

#[test]
fn validates_group_and_materialized_fallback() {
    let first = frame(100, Some(99), TcpControl::None, b"abcd");
    let last = frame(104, Some(99), TcpControl::Psh, b"efg");
    let caps = ChecksumCapabilities::default();
    let gro = TcpGro::new(&[&first, &last], &caps).unwrap();
    assert_eq!(gro.payloads(), &[&b"abcd"[..], &b"efg"[..]]);
    let bytes = gro.materialize();
    assert_eq!(&bytes[54..], b"abcdefg");
    let ip = Ipv4Packet::new_checked(&bytes[14..]).unwrap();
    assert!(ip.verify_checksum());
    let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
    assert!(tcp.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into()));
    assert_eq!(tcp.psh(), true);
    let mut bad = last.clone(); bad[54] ^= 1;
    assert!(TcpGro::new(&[&first, &bad], &caps).is_none());
    assert!(TcpGro::new(&[&first, &bad], &ChecksumCapabilities::ignored()).is_some());
    for n in 0..last.len() {
        assert!(TcpGro::new(&[&first, &last[..n]], &caps).is_none());
    }
    assert!(TcpGro::new(&[first.as_slice(); 17], &caps).is_none());
}

#[test]
fn incremental_rejection_preserves_prefix_and_checksum_policy() {
    let first = frame(-4, Some(99), TcpControl::None, b"abcd");
    let second = frame(0, Some(99), TcpControl::None, b"efgh");
    let last = frame(4, Some(99), TcpControl::Psh, b"ijk");
    let mut corrupt = second.clone(); corrupt[54] ^= 1;
    let wrong_sequence = frame(1, Some(99), TcpControl::None, b"efgh");
    let mut caps = ChecksumCapabilities::default();
    let mut builder = TcpGroBuilder::new(&first, &caps).unwrap();
    caps.tcp = crate::phy::Checksum::None; // Cannot weaken the captured policy.
    assert_eq!(builder.push(&corrupt), Err(TcpGroReject::Ineligible));
    assert_eq!(builder.push(&wrong_sequence), Err(TcpGroReject::Incompatible));
    assert_eq!(builder.segment_count(), 1);
    builder.push(&second).unwrap();
    builder.push(&last).unwrap();
    assert!(builder.is_finished());
    assert_eq!(builder.push(&second), Err(TcpGroReject::Finished));
    let group = builder.finish().unwrap();
    assert_eq!(group.payloads(), &[&b"abcd"[..], &b"efgh"[..], &b"ijk"[..]]);
    assert_eq!(group.materialize(), TcpGro::new(&[&first, &second, &last], &ChecksumCapabilities::default()).unwrap().materialize());
    assert!(TcpGroBuilder::new(&first, &caps).unwrap().finish().is_none());
}

#[test]
fn nic_checksum_is_scoped_to_one_ipv4_tcp_member() {
    let first = frame(-4, Some(99), TcpControl::None, b"abcd");
    let mut second = frame(0, Some(99), TcpControl::None, b"efgh");
    let mut last = frame(4, Some(99), TcpControl::Psh, b"ijkl");
    let caps = ChecksumCapabilities::default();
    let mut meta = crate::phy::PacketMeta::default();
    meta.rx_tcp_checksum_verified = true;
    // A descriptor may verify TCP even when its received checksum field is absent.
    second[50..52].fill(0);
    assert!(TcpGroBuilder::new_bounded(&first, &caps, meta, first.len() - 1).is_none());
    let mut bounded = TcpGroBuilder::new_bounded(&first, &caps, meta, first.len() + 3).unwrap();
    assert_eq!(bounded.push_with_meta(&second, meta), Err(TcpGroReject::Capacity));
    let mut builder = TcpGroBuilder::new_bounded(&first, &caps, meta, 16384).unwrap();
    assert_eq!(builder.push(&second), Err(TcpGroReject::Ineligible));
    builder.push_with_meta(&second, meta).unwrap();
    last[24] ^= 1; // IPv4 is still checked on a TCP-verified frame.
    assert_eq!(builder.push_with_meta(&last, meta), Err(TcpGroReject::Ineligible));
    let group = builder.finish().unwrap();
    assert!(group.satisfies_checksum_policy(&caps));
    assert_eq!(group.payloads(), &[&b"abcd"[..], &b"efgh"[..]]);
}

#[test]
fn incremental_bounds_and_terminal_segments_preserve_accepted_data() {
    let caps = ChecksumCapabilities::default();
    let max = crate::phy::TCP_GRO_MAX_SEGMENTS;
    let frames: Vec<Vec<u8>> = (0..=max).map(|i| frame(4*i as i32, Some(99), TcpControl::None, b"data")).collect();
    let mut builder = TcpGroBuilder::new(&frames[0], &caps).unwrap();
    for f in &frames[1..max] { builder.push(f).unwrap(); }
    assert!(builder.is_finished());
    assert_eq!(builder.push(&frames[max]), Err(TcpGroReject::Capacity));
    assert_eq!(builder.finish().unwrap().payloads().len(), max);

    let bytes = vec![42; (crate::phy::TCP_GRO_MAX_BYTES-54)/2];
    let first = frame(0, Some(99), TcpControl::None, &bytes);
    let second = frame(bytes.len() as i32, Some(99), TcpControl::None, &bytes);
    let extra = frame((bytes.len()*2) as i32, Some(99), TcpControl::None, &bytes);
    let mut builder = TcpGroBuilder::new(&first, &caps).unwrap();
    builder.push(&second).unwrap();
    assert_eq!(builder.push(&extra), Err(TcpGroReject::Capacity));
    assert_eq!(builder.finish().unwrap().materialize().len(), crate::phy::TCP_GRO_MAX_BYTES);

    let short = frame(4, Some(99), TcpControl::None, b"x");
    let following = frame(5, Some(99), TcpControl::None, b"y");
    let mut builder = TcpGroBuilder::new(&frames[0], &caps).unwrap();
    builder.push(&short).unwrap();
    assert_eq!(builder.push(&following), Err(TcpGroReject::Finished));
    assert_eq!(builder.finish().unwrap().payloads(), &[&b"data"[..], &b"x"[..]]);
    let psh = frame(0, Some(99), TcpControl::Psh, b"data");
    let mut builder = TcpGroBuilder::new(&psh, &caps).unwrap();
    assert_eq!(builder.push(&frames[1]), Err(TcpGroReject::Finished));
    assert!(builder.finish().is_none());
}

#[test]
fn checked_token_keeps_interface_checksum_and_address_admission() {
    struct CheckedDevice { inner: GroupDevice, weak: bool }
    struct CheckedRx { frames: Vec<Vec<u8>>, weak: bool }
    impl RxTrait for CheckedRx {
        fn consume<R, F: FnOnce(&[u8]) -> R>(self, _: F) -> R {
            panic!("checked-token test must use the checked receive entry")
        }
        fn consume_gro_checked<R, F: FnOnce(crate::phy::TcpGroRx<'_>) -> R>(
            self, caps: &ChecksumCapabilities, f: F,
        ) -> R {
            let caps = if self.weak { ChecksumCapabilities::ignored() } else { caps.clone() };
            let mut builder = TcpGroBuilder::new(&self.frames[0], &caps).unwrap();
            for frame in &self.frames[1..] { builder.push(frame).unwrap(); }
            f(crate::phy::TcpGroRx::Group(builder.finish().unwrap()))
        }
    }
    impl Device for CheckedDevice {
        type RxToken<'a> = CheckedRx;
        type TxToken<'a> = GroupTx<'a>;
        fn capabilities(&self) -> DeviceCapabilities { self.inner.capabilities() }
        fn receive(&mut self, _: Instant) -> Option<(CheckedRx, GroupTx<'_>)> {
            Some((CheckedRx { frames: self.inner.frames.take()?, weak: self.weak }, GroupTx(&mut self.inner.sent)))
        }
        fn transmit(&mut self, _: Instant) -> Option<GroupTx<'_>> { Some(GroupTx(&mut self.inner.sent)) }
    }
    for (weak, wrong_address) in [(false, false), (true, false), (false, true)] {
        let (mut iface, mut sockets, _) = setup(Medium::Ethernet);
        iface.inner.neighbor_cache.fill(IpAddress::v4(192,168,1,2),
            HardwareAddress::Ethernet(EthernetAddress([2,2,2,2,2,3])), Instant::ZERO);
        let mut frames = vec![frame(100, Some(99), TcpControl::None, b"abcd"), frame(104, Some(99), TcpControl::Psh, b"efgh")];
        if wrong_address {
            for frame in &mut frames { frame[0] = 4; }
        }
        let mut device = CheckedDevice { inner: GroupDevice { frames: Some(frames), sent: Vec::new() }, weak };
        iface.poll(Instant::from_millis(1), &mut device, &mut sockets);
        // No listener: a valid admitted TCP segment gets a reset. Weak proofs
        // and wrong destination MAC must be dropped before TCP dispatch.
        let resets = device.inner.sent.iter().filter(|bytes| {
            let eth = EthernetFrame::new_checked(bytes.as_slice()).unwrap();
            if eth.ethertype() != EthernetProtocol::Ipv4 { return false; }
            let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
            ip.next_header() == IpProtocol::Tcp && TcpPacket::new_checked(ip.payload()).unwrap().rst()
        }).count();
        assert_eq!(resets, usize::from(!weak && !wrong_address));
    }
}

#[test]
fn checked_policy_requires_each_requested_checksum_independently() {
    let first = frame(0, Some(99), TcpControl::None, b"abcd");
    let last = frame(4, Some(99), TcpControl::Psh, b"efgh");
    for verified_ip in [false, true] {
        for verified_tcp in [false, true] {
            let mut verified = ChecksumCapabilities::ignored();
            if verified_ip { verified.ipv4 = crate::phy::Checksum::Rx; }
            if verified_tcp { verified.tcp = crate::phy::Checksum::Rx; }
            let group = TcpGro::new(&[&first, &last], &verified).unwrap();
            for require_ip in [false, true] {
                for require_tcp in [false, true] {
                    let mut required = ChecksumCapabilities::ignored();
                    if require_ip { required.ipv4 = crate::phy::Checksum::Rx; }
                    if require_tcp { required.tcp = crate::phy::Checksum::Rx; }
                    assert_eq!(group.satisfies_checksum_policy(&required),
                        (!require_ip || verified_ip) && (!require_tcp || verified_tcp));
                }
            }
        }
    }
}

#[test]
fn grouped_token_uses_normal_address_admission_and_delivers_complete_payload() {
    let (mut iface, mut sockets, _) = setup(Medium::Ethernet);
    let mut device = GroupDevice::default();
    #[cfg(feature = "socket-raw")]
    let raw_handle = {
        use crate::socket::raw;
        sockets.add(raw::Socket::new(Some(IpVersion::Ipv4), Some(IpProtocol::Tcp),
            raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; 16], vec![0; 4096]),
            raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; 1], vec![0; 128])))
    };
    let mut socket = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; 64]), tcp::SocketBuffer::new(vec![0; 64]));
    socket.set_ack_delay(None); socket.listen(80).unwrap(); let handle = sockets.add(socket);
    iface.inner.neighbor_cache.fill(IpAddress::v4(192,168,1,2),
        HardwareAddress::Ethernet(EthernetAddress([2,2,2,2,2,3])), Instant::ZERO);
    device.frames = Some(vec![frame(100, None, TcpControl::Syn, &[])]);
    iface.poll(Instant::from_millis(1), &mut device, &mut sockets);
    let reply = TcpPacket::new_checked(&device.sent.last().unwrap()[34..]).unwrap();
    assert!(reply.syn()); let ack = (reply.seq_number() + 1).0;
    device.frames = Some(vec![frame(101, Some(ack), TcpControl::None, &[])]);
    iface.poll(Instant::from_millis(2), &mut device, &mut sockets);
    assert_eq!(sockets.get::<tcp::Socket>(handle).state(), tcp::State::Established);
    for case in 0..6 {
        let mut frames = vec![frame(101, Some(ack), TcpControl::None, b"abcd"),
            frame(105, Some(ack), TcpControl::Psh, b"efgh")];
        for b in &mut frames {
            match case {
                0 => b[5] = 9, // wrong destination MAC, otherwise valid
                1 => b[33] = 99, // wrong destination IP, otherwise valid
                2 => b[26] = 224, // multicast source is inadmissible
                _ => (),
            }
            checksums(b);
        }
        match case {
            3 => frames[1][54] ^= 1, // bad second checksum must not admit first data
            4 => { frames[1][41] ^= 1; checksums(&mut frames[1]); },
            5 => { frames[0][47] |= 8; checksums(&mut frames[0]); },
            _ => (),
        }
        device.sent.clear(); device.frames = Some(frames);
        iface.poll(Instant::from_millis(3 + case), &mut device, &mut sockets);
        assert_eq!(sockets.get::<tcp::Socket>(handle).recv_queue(), 0, "case {case}");
        assert!(device.sent.is_empty(), "case {case}");
    }
    #[cfg(feature = "socket-raw")]
    while sockets.get_mut::<crate::socket::raw::Socket>(raw_handle).recv().is_ok() {}
    device.frames = Some(vec![frame(101, Some(ack), TcpControl::None, b"abcd"),
        frame(105, Some(ack), TcpControl::Psh, b"efgh")]);
    iface.poll(Instant::from_millis(10), &mut device, &mut sockets);
    let mut out = [0; 8];
    assert_eq!(sockets.get_mut::<tcp::Socket>(handle).recv_slice(&mut out), Ok(8));
    assert_eq!(&out, b"abcdefgh");
    let reply = TcpPacket::new_checked(&device.sent.last().unwrap()[34..]).unwrap();
    assert_eq!(reply.ack_number(), TcpSeqNumber(109));
    #[cfg(feature = "socket-raw")]
    {
        let packet = sockets.get_mut::<crate::socket::raw::Socket>(raw_handle).recv().unwrap();
        let ip = Ipv4Packet::new_checked(packet).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!(tcp.payload(), b"abcdefgh");
        assert!(ip.verify_checksum());
        assert!(tcp.verify_checksum(&ip.src_addr().into(), &ip.dst_addr().into()));
    }
}

#[cfg(feature = "tcp-gro-wide")]
#[test]
fn wide_mtu_group_preserves_byte_limit_and_rejected_successor() {
    let count = crate::phy::TCP_GRO_MAX_SEGMENTS.min((crate::phy::TCP_GRO_MAX_BYTES - 54) / 1460);
    let payload = vec![0x71; 1460];
    let frames: Vec<_> = (0..=count).map(|i| frame((i * 1460) as i32, Some(99), TcpControl::None, &payload)).collect();
    let mut builder = TcpGroBuilder::new(&frames[0], &ChecksumCapabilities::default()).unwrap();
    for f in &frames[1..count] { builder.push(f).unwrap(); }
    assert_eq!(builder.push(&frames[count]), Err(TcpGroReject::Capacity));
    assert_eq!(builder.segment_count(), count);
    let group = builder.finish().unwrap();
    assert_eq!(group.payloads().len(), count);
    let bytes = group.materialize();
    assert_eq!(bytes.len(), 54 + count * 1460);
    assert!(bytes.len() <= crate::phy::TCP_GRO_MAX_BYTES);
    assert_eq!(&bytes[54..], vec![0x71; count * 1460].as_slice());
    // The rejected frame is unchanged and can begin the following group.
    let next = TcpGroBuilder::new(&frames[count], &ChecksumCapabilities::default()).unwrap();
    assert_eq!(next.segment_count(), 1);
}

#[cfg(feature = "tcp-gro-wide")]
#[test]
fn wide_group_delivers_all_fragments_through_tcp_socket() {
    let (mut iface, mut sockets, _) = setup(Medium::Ethernet);
    let mut device = GroupDevice::default();
    let mut socket = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; 65536]), tcp::SocketBuffer::new(vec![0; 64]));
    socket.set_ack_delay(None); socket.listen(80).unwrap(); let handle = sockets.add(socket);
    iface.inner.neighbor_cache.fill(IpAddress::v4(192,168,1,2),
        HardwareAddress::Ethernet(EthernetAddress([2,2,2,2,2,3])), Instant::ZERO);
    device.frames = Some(vec![frame(100, None, TcpControl::Syn, &[])]);
    iface.poll(Instant::from_millis(1), &mut device, &mut sockets);
    let reply = TcpPacket::new_checked(&device.sent.last().unwrap()[34..]).unwrap();
    let ack = (reply.seq_number() + 1).0;
    device.frames = Some(vec![frame(101, Some(ack), TcpControl::None, &[])]);
    iface.poll(Instant::from_millis(2), &mut device, &mut sockets);
    let count = crate::phy::TCP_GRO_MAX_SEGMENTS.min((crate::phy::TCP_GRO_MAX_BYTES - 54) / 1460);
    let expected: Vec<u8> = (0..count*1460).map(|i| ((i * 17 + i / 251) % 253) as u8).collect();
    device.frames = Some(expected.chunks(1460).enumerate().map(|(i, bytes)|
        frame(101 + (i * 1460) as i32, Some(ack), TcpControl::None, bytes)).collect());
    iface.poll(Instant::from_millis(3), &mut device, &mut sockets);
    let mut received = vec![0; expected.len()];
    assert_eq!(sockets.get_mut::<tcp::Socket>(handle).recv_slice(&mut received), Ok(expected.len()));
    assert_eq!(received, expected);
    let reply = TcpPacket::new_checked(&device.sent.last().unwrap()[34..]).unwrap();
    assert_eq!(reply.ack_number(), TcpSeqNumber(101 + expected.len() as i32));
}
