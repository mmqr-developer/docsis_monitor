// Copyright MMQR Development
//! Reading a captured frame far enough to say what it is.
//!
//! Ethernet, then `IPv4` or `IPv6`, then UDP, then the port numbers. That is all
//! this program needs: it counts packets, it does not interpret DHCP.
//!
//! Hand-written rather than a packet-parsing crate, because this is the part
//! that has to be RIGHT and the part a test can drive without a network card.
//! Everything below takes a byte slice and returns a verdict, so the whole of
//! it is exercised by tests on this machine, with no interface, no privileges
//! and no traffic.
//!
//! Every field is read with a bounds check. A capture is the one input in this
//! repository that arrives from outside the plant entirely -- anyone who can
//! put a frame on the wire can put anything they like in it -- so a truncated
//! or lying header must produce None, never a panic in a process that is
//! supposed to still be watching an hour later.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// UDP ports that mean provisioning.
///
/// 67 and 68 are `DHCPv4`, server and client. 546 and 547 are `DHCPv6`. 69 is
/// TFTP, and only the request goes there -- the transfer itself moves to an
/// ephemeral port on both ends, which is why a config file that is being
/// SERVED is counted once, at the point a modem asks for it. That is the
/// number worth having anyway: a modem that asks and gets nothing is the
/// failure, and it leaves exactly one packet behind.
pub const DHCP_SERVER: u16 = 67;
pub const DHCP_CLIENT: u16 = 68;
pub const DHCP6_CLIENT: u16 = 546;
pub const DHCP6_SERVER: u16 = 547;
pub const TFTP: u16 = 69;

/// What a frame turned out to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seen {
    pub kind: Kind,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    /// The gi-address the relay stamped on a `DHCPv4` packet, when there is
    /// one.
    ///
    /// This is the field that says WHICH CMTS interface a request came
    /// through, and it is the one an operator needs: the source address of a
    /// relayed request is the relay, and one relay fronts many interfaces.
    /// The server picks the pool from it, so a request with the wrong
    /// gi-address is refused for a reason nothing else on the wire explains.
    pub gi: Option<Ipv4Addr>,
    /// The transaction id, on a DHCP packet.
    ///
    /// A request and the reply that answers it carry the same one. That is
    /// what lets this say whether a request was answered AND HOW FAST,
    /// without guessing from counts: two thousand requests and two thousand
    /// replies in a window can be a plant answering everything in four
    /// milliseconds or one answering half of them twice, four seconds late.
    pub xid: Option<u32>,
    /// The UDP payload length, which is what a quiet-but-not-silent plant is
    /// distinguished by: keepalives are small and configurations are not.
    pub bytes: usize,
}

/// The four things worth counting separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// A client asking: DISCOVER, REQUEST, SOLICIT and the rest. Anything
    /// going TO a server port.
    ClientRequest,
    /// A server answering: OFFER, ACK, NAK, ADVERTISE, REPLY. Anything coming
    /// FROM a server port.
    ServerReply,
    /// A modem asking for a configuration file: a read request, and nothing
    /// else. NOT every packet a modem sends to port 69.
    TftpRequest,
    /// The server answering: data, an option acknowledgement, or an error.
    TftpReply,
}

/// Reads one Ethernet frame, or decides it is none of this program's business.
///
/// `None` is the ordinary answer. Most of what crosses a plant's interface is
/// not DHCP or TFTP, and this is called once per frame.
#[must_use]
pub fn read(frame: &[u8]) -> Option<Seen> {
    let (ethertype, rest) = ethernet(frame)?;
    let (src, dst, proto, payload) = match ethertype {
        0x0800 => ipv4(rest)?,
        0x86DD => ipv6(rest)?,
        _ => return None,
    };
    if proto != 17 {
        return None; // not UDP
    }
    let (sport, dport, len, body) = udp(payload)?;
    let kind = classify(sport, dport, body)?;
    Some(Seen {
        kind,
        src,
        dst,
        sport,
        dport,
        gi: giaddr(sport, dport, body),
        xid: xid(sport, dport, body),
        bytes: len,
    })
}

/// The gi-address out of a `DHCPv4` packet, when it carries one.
///
/// Bytes 24 to 27 of the BOOTP header. Zero means "no relay was involved",
/// which is a real answer and not a missing one -- but it is not a gi-address,
/// so it comes back as None rather than as 0.0.0.0 in a column of addresses.
///
/// `DHCPv6` has no equivalent in the packet itself: the link-address lives in
/// a RELAY-FORW header, which is a different shape, and a plant that relays
/// v6 is not what this is for yet.
fn giaddr(sport: u16, dport: u16, body: &[u8]) -> Option<Ipv4Addr> {
    if !matches!(
        (sport, dport),
        (DHCP_SERVER | DHCP_CLIENT, DHCP_SERVER | DHCP_CLIENT)
    ) {
        return None;
    }
    let gi = Ipv4Addr::from(quad(body, 24)?);
    if gi.is_unspecified() { None } else { Some(gi) }
}

/// The ethertype and what follows it, with VLAN tags stepped over.
///
/// A plant's provisioning interface is very often a trunk, so the tag is the
/// normal case rather than the exception. Two of them are stepped over --
/// 802.1ad outer plus 802.1Q inner is how a wholesale hand-off arrives -- and
/// no more, because a frame claiming twenty tags is not a frame.
fn ethernet(frame: &[u8]) -> Option<(u16, &[u8])> {
    let mut at = 12; // past the two MAC addresses
    let mut ethertype = be16(frame, at)?;
    for _ in 0..2 {
        if ethertype == 0x8100 || ethertype == 0x88A8 {
            at += 4;
            ethertype = be16(frame, at)?;
        } else {
            break;
        }
    }
    let rest = frame.get(at + 2..)?;
    Some((ethertype, rest))
}

/// Source, destination, protocol and payload of an `IPv4` packet.
fn ipv4(b: &[u8]) -> Option<(IpAddr, IpAddr, u8, &[u8])> {
    let first = *b.first()?;
    if first >> 4 != 4 {
        return None;
    }
    // The header length is in 32-bit words and has a floor of five. A packet
    // claiming less is malformed, and trusting it would slice backwards.
    let ihl = usize::from(first & 0x0F) * 4;
    if ihl < 20 {
        return None;
    }
    let proto = *b.get(9)?;
    let src = Ipv4Addr::from(quad(b, 12)?);
    let dst = Ipv4Addr::from(quad(b, 16)?);
    // A fragment that is not the first has no UDP header in it. Counting one
    // would be counting a packet that is half of something already counted.
    let frag = be16(b, 6)?;
    if frag & 0x1FFF != 0 {
        return None;
    }
    Some((IpAddr::V4(src), IpAddr::V4(dst), proto, b.get(ihl..)?))
}

/// The same for `IPv6`, following the extension headers this program can meet.
///
/// Hop-by-hop, routing and destination options are all "next header, length in
/// 8-octet units after the first". Fragment headers are a fixed eight bytes.
/// Anything else -- ESP, an unknown number -- ends the walk, because the
/// payload after it is not a UDP header and guessing would count noise.
fn ipv6(b: &[u8]) -> Option<(IpAddr, IpAddr, u8, &[u8])> {
    if b.first()? >> 4 != 6 {
        return None;
    }
    let src = Ipv6Addr::from(sixteen(b, 8)?);
    let dst = Ipv6Addr::from(sixteen(b, 24)?);
    let mut next = *b.get(6)?;
    let mut at = 40;
    // Bounded, because an extension header claiming a length of zero would
    // otherwise walk this loop for ever on a crafted frame.
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                let len = (usize::from(*b.get(at + 1)?) + 1) * 8;
                next = *b.get(at)?;
                at += len;
            }
            44 => {
                next = *b.get(at)?;
                at += 8;
            }
            _ => break,
        }
    }
    Some((IpAddr::V6(src), IpAddr::V6(dst), next, b.get(at..)?))
}

/// Ports, payload length, and the payload itself.
///
/// The length comes from the HEADER and the payload from the frame, and they
/// disagree whenever a capture is truncated. Both are returned because they
/// answer different questions: the length is what was carried, and the bytes
/// are what this program can actually look at.
fn udp(b: &[u8]) -> Option<(u16, u16, usize, &[u8])> {
    let sport = be16(b, 0)?;
    let dport = be16(b, 2)?;
    // The length field covers the header as well, so anything under eight is
    // a lie.
    let len = usize::from(be16(b, 4)?);
    if len < 8 {
        return None;
    }
    Some((sport, dport, len - 8, b.get(8..).unwrap_or(&[])))
}

/// Which of the four kinds a packet is, if any.
///
/// The ports say WHETHER this is provisioning. What they cannot say is which
/// way it is going.
///
/// On a DOCSIS plant a CMTS relays, and a relayed conversation travels 67 to
/// 67 in BOTH directions -- the relay's request to the server and the
/// server's answer back to the relay carry the same pair of ports. Deciding
/// on ports alone counted every answer as another request, so a plant being
/// served perfectly read as one where nothing was ever answered. That is a
/// false alarm on a working plant, which is the worst thing a monitor can do:
/// it is the failure that teaches people to ignore it.
///
/// So the direction comes from the message itself. `DHCPv4` opens with `op`:
/// 1 is a request, 2 is a reply, and that is true whether the packet was
/// relayed, broadcast, or sent straight to the server. `DHCPv6` opens with
/// its message type, and the handful the SERVER sends are listed below.
///
/// A packet with no payload to read falls back to the ports, which is right
/// for the only case that produces one: a capture truncated by a snaplen.
#[must_use]
pub fn classify(sport: u16, dport: u16, body: &[u8]) -> Option<Kind> {
    match (sport, dport) {
        (_, TFTP) | (TFTP, _) => tftp_kind(body),
        (DHCP_SERVER | DHCP_CLIENT, DHCP_SERVER | DHCP_CLIENT) => Some(match body.first() {
            Some(2) => Kind::ServerReply,
            Some(_) => Kind::ClientRequest,
            None => port_direction(sport, dport),
        }),
        (DHCP6_SERVER | DHCP6_CLIENT, DHCP6_SERVER | DHCP6_CLIENT) => Some(match body.first() {
            Some(t) if is_dhcp6_server_message(*t) => Kind::ServerReply,
            Some(_) => Kind::ClientRequest,
            None => port_direction(sport, dport),
        }),
        _ => None,
    }
}

/// The transaction id, which a request and its answer share.
///
/// `DHCPv4` puts it in bytes 4 to 7. `DHCPv6` puts a three-byte one straight
/// after the message type, which is widened here so both fit one field; three
/// bytes of transaction id cannot collide with a four-byte one in practice
/// because the two never appear in the same conversation.
fn xid(sport: u16, dport: u16, body: &[u8]) -> Option<u32> {
    match (sport, dport) {
        (DHCP_SERVER | DHCP_CLIENT, DHCP_SERVER | DHCP_CLIENT) => {
            Some(u32::from_be_bytes(quad(body, 4)?))
        }
        (DHCP6_SERVER | DHCP6_CLIENT, DHCP6_SERVER | DHCP6_CLIENT) => Some(
            (u32::from(*body.get(1)?) << 16)
                | (u32::from(*body.get(2)?) << 8)
                | u32::from(*body.get(3)?),
        ),
        _ => None,
    }
}

/// Which of the four kinds a TFTP packet is -- or none at all.
///
/// The OPCODE, not the port. This server keeps port 69 for the whole
/// transfer, so a fetch is a read request, a data block, and an
/// acknowledgement, and two of those three have port 69 as their DESTINATION.
/// Counting by port made every ACK another read request: with a config small
/// enough to fit in one block, "tftp reads" came out at exactly twice the
/// number of files fetched, and a bigger config would have made it worse.
///
/// An acknowledgement is counted as NEITHER. It is flow control. What an
/// operator reads "tftp reads" as is how many modems asked for a
/// configuration, and that is what it now says.
fn tftp_kind(body: &[u8]) -> Option<Kind> {
    // Two bytes, big-endian. 1 RRQ, 2 WRQ, 3 DATA, 4 ACK, 5 ERROR, 6 OACK.
    match be16(body, 0)? {
        1 | 2 => Some(Kind::TftpRequest),
        3 | 5 | 6 => Some(Kind::TftpReply),
        _ => None,
    }
}

/// The `DHCPv6` message types a SERVER sends.
///
/// ADVERTISE, REPLY, RECONFIGURE and RELAY-REPL. Everything else in the
/// registry is a client's, or a relay carrying a client's.
const fn is_dhcp6_server_message(t: u8) -> bool {
    matches!(t, 2 | 7 | 10 | 13)
}

/// The direction a pair of ports suggests, for a packet with no payload left
/// to read. A guess, and only ever reached on a truncated capture.
const fn port_direction(sport: u16, dport: u16) -> Kind {
    match (sport, dport) {
        (DHCP_SERVER | DHCP6_SERVER, DHCP_CLIENT | DHCP6_CLIENT) => Kind::ServerReply,
        _ => Kind::ClientRequest,
    }
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn quad(b: &[u8], at: usize) -> Option<[u8; 4]> {
    b.get(at..at + 4)?.try_into().ok()
}

fn sixteen(b: &[u8], at: usize) -> Option<[u8; 16]> {
    b.get(at..at + 16)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a frame: Ethernet, `IPv4`, UDP, and nothing after it.
    /// A frame whose payload opens with `op`, which is what decides a
    /// `DHCPv4` packet's direction.
    fn v4op(op: u8, sport: u16, dport: u16, src: [u8; 4], dst: [u8; 4], payload: usize) -> Vec<u8> {
        let mut f = v4(sport, dport, src, dst, payload);
        if payload > 0 {
            // Zeroed, not filler: a BOOTP header is mostly zero, and filler
            // would put 0xABABABAB in the gi-address field of a packet no
            // relay touched.
            let at = f.len() - payload;
            for b in &mut f[at..] {
                *b = 0;
            }
            f[at] = op;
        }
        f
    }

    fn v4(sport: u16, dport: u16, src: [u8; 4], dst: [u8; 4], payload: usize) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend([0x08, 0x00]); // IPv4
        let mut ip = vec![0x45, 0x00];
        ip.extend((20u16 + 8 + u16::try_from(payload).unwrap()).to_be_bytes());
        ip.extend([0, 0, 0, 0]); // id, flags, fragment offset
        ip.extend([64, 17]); // ttl, UDP
        ip.extend([0, 0]); // checksum
        ip.extend(src);
        ip.extend(dst);
        ip.extend(sport.to_be_bytes());
        ip.extend(dport.to_be_bytes());
        ip.extend((8u16 + u16::try_from(payload).unwrap()).to_be_bytes());
        ip.extend([0, 0]); // checksum
        ip.extend(std::iter::repeat_n(0xAB, payload));
        f.extend(ip);
        f
    }

    /// A TFTP frame whose payload opens with `opcode`.
    fn tftp(opcode: u16, sport: u16, dport: u16, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut f = v4(sport, dport, src, dst, 40);
        let at = f.len() - 40;
        f[at..at + 2].copy_from_slice(&opcode.to_be_bytes());
        f
    }

    fn ip4(a: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(a))
    }

    #[test]
    fn a_relayed_discover_reads_as_a_client_request() {
        // 67 to 67 is what a CMTS relay sends. On a DOCSIS plant this is the
        // ordinary shape and almost nothing arrives from port 68 at all.
        let f = v4op(
            1,
            DHCP_SERVER,
            DHCP_SERVER,
            [10, 0, 0, 1],
            [10, 0, 0, 9],
            300,
        );
        let seen = read(&f).expect("a DHCP packet");
        assert_eq!(seen.kind, Kind::ClientRequest);
        assert_eq!(seen.src, ip4([10, 0, 0, 1]));
        assert_eq!(seen.dst, ip4([10, 0, 0, 9]));
        assert_eq!(seen.bytes, 300);
    }

    // THE ONE THAT MATTERS. A relayed conversation travels 67 to 67 in both
    // directions, so ports alone counted every answer as another request --
    // and a plant being served perfectly read as one where nothing was ever
    // answered. That is a false alarm on a working plant, which is the
    // failure that teaches people to ignore a monitor. It was caught on the
    // test VM, where 95,784 requests and 0 replies were reported for a plant
    // that had just handed out twelve thousand leases.
    #[test]
    fn an_offer_relayed_back_on_the_same_ports_is_a_reply() {
        let f = v4op(
            2,
            DHCP_SERVER,
            DHCP_SERVER,
            [10, 0, 0, 9],
            [10, 0, 0, 1],
            300,
        );
        assert_eq!(
            read(&f).expect("a DHCP packet").kind,
            Kind::ServerReply,
            "op=2 is a BOOTREPLY whichever ports carried it"
        );
    }

    #[test]
    fn an_offer_straight_to_a_client_is_also_a_reply() {
        let f = v4op(
            2,
            DHCP_SERVER,
            DHCP_CLIENT,
            [10, 0, 0, 9],
            [10, 0, 0, 1],
            300,
        );
        assert_eq!(read(&f).expect("a DHCP packet").kind, Kind::ServerReply);
    }

    // DHCPv6 has no op field; the message type is the first byte, and only a
    // handful of them are the server's.
    #[test]
    fn dhcpv6_directions_come_from_the_message_type() {
        for (t, want) in [
            (1u8, Kind::ClientRequest), // SOLICIT
            (2, Kind::ServerReply),     // ADVERTISE
            (3, Kind::ClientRequest),   // REQUEST
            (7, Kind::ServerReply),     // REPLY
            (10, Kind::ServerReply),    // RECONFIGURE
            (12, Kind::ClientRequest),  // RELAY-FORW
            (13, Kind::ServerReply),    // RELAY-REPL
        ] {
            assert_eq!(
                classify(DHCP6_SERVER, DHCP6_SERVER, &[t]),
                Some(want),
                "DHCPv6 message type {t}"
            );
        }
    }

    // A capture cut short by a snaplen has ports and nothing else. The ports
    // are then the only thing to go on, and are right for the direct case.
    #[test]
    fn with_no_payload_left_the_ports_are_all_there_is() {
        assert_eq!(
            classify(DHCP_SERVER, DHCP_CLIENT, &[]),
            Some(Kind::ServerReply)
        );
        assert_eq!(
            classify(DHCP_CLIENT, DHCP_SERVER, &[]),
            Some(Kind::ClientRequest)
        );
    }

    // THE SECOND ONE THAT MATTERED. This server keeps port 69 for the whole
    // transfer, so a fetch is a read request, a data block and an
    // acknowledgement -- and TWO of those three have port 69 as their
    // destination. Counting by port made every ACK another read request, and
    // "tftp reads" came out at exactly twice the number of files fetched on
    // the test VM: 8,000 for 4,000 modems.
    //
    // An acknowledgement is now counted as neither. What an operator reads
    // "tftp reads" as is how many modems asked for a configuration.
    #[test]
    fn a_whole_tftp_fetch_is_one_read_and_one_send() {
        let rrq = tftp(1, 50_000, TFTP, [10, 100, 0, 19], [192, 168, 122, 93]);
        let data = tftp(3, TFTP, 50_000, [192, 168, 122, 93], [10, 100, 0, 19]);
        let ack = tftp(4, 50_000, TFTP, [10, 100, 0, 19], [192, 168, 122, 93]);

        assert_eq!(read(&rrq).expect("a read request").kind, Kind::TftpRequest);
        assert_eq!(read(&data).expect("a data block").kind, Kind::TftpReply);
        assert!(
            read(&ack).is_none(),
            "an acknowledgement is flow control, not a modem asking for a file"
        );

        // An error from the server is an answer, and the one worth seeing.
        let err = tftp(5, TFTP, 50_000, [192, 168, 122, 93], [10, 100, 0, 19]);
        assert_eq!(read(&err).expect("an error").kind, Kind::TftpReply);
        // And an option acknowledgement, which a modem asking for a blksize
        // gets first.
        let oack = tftp(6, TFTP, 50_000, [192, 168, 122, 93], [10, 100, 0, 19]);
        assert_eq!(read(&oack).expect("an OACK").kind, Kind::TftpReply);
    }

    // A request and its answer share a transaction id. That is what turns
    // "two thousand replies" into "two thousand requests answered, in four
    // milliseconds" -- which is a different fact, and the one worth having.
    #[test]
    fn a_request_and_its_answer_share_a_transaction_id() {
        let mut req = v4op(
            1,
            DHCP_SERVER,
            DHCP_SERVER,
            [10, 0, 0, 1],
            [10, 0, 0, 9],
            300,
        );
        let at = req.len() - 300 + 4;
        req[at..at + 4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut rep = v4op(
            2,
            DHCP_SERVER,
            DHCP_SERVER,
            [10, 0, 0, 9],
            [10, 0, 0, 1],
            300,
        );
        rep[at..at + 4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        assert_eq!(read(&req).expect("a request").xid, Some(0xDEAD_BEEF));
        assert_eq!(read(&rep).expect("a reply").xid, Some(0xDEAD_BEEF));
        // TFTP has none, and must not be given one from whatever bytes
        // happen to sit at that offset.
        let t = tftp(1, 50_000, TFTP, [10, 0, 0, 1], [10, 0, 0, 9]);
        assert_eq!(read(&t).expect("a TFTP packet").xid, None);
    }

    #[test]
    fn dhcpv6_transaction_ids_are_three_bytes_after_the_message_type() {
        assert_eq!(
            xid(DHCP6_CLIENT, DHCP6_SERVER, &[1, 0x11, 0x22, 0x33]),
            Some(0x0011_2233)
        );
    }

    // The gi-address is the field that says WHICH interface a request came
    // through. The source of a relayed request is the relay, and one relay
    // fronts many interfaces.
    #[test]
    fn a_relayed_request_carries_its_gi_address() {
        let mut f = v4op(
            1,
            DHCP_SERVER,
            DHCP_SERVER,
            [10, 0, 0, 1],
            [10, 0, 0, 9],
            300,
        );
        let at = f.len() - 300 + 24;
        f[at..at + 4].copy_from_slice(&[10, 100, 0, 1]);
        let seen = read(&f).expect("a DHCP packet");
        assert_eq!(seen.gi, Some(Ipv4Addr::new(10, 100, 0, 1)));
    }

    // Zero means no relay was involved. That is a real answer, and it is not
    // an address: putting 0.0.0.0 in a column of gi-addresses would read as
    // one.
    #[test]
    fn an_unrelayed_request_has_no_gi_address() {
        let f = v4op(
            1,
            DHCP_CLIENT,
            DHCP_SERVER,
            [10, 0, 0, 1],
            [10, 0, 0, 9],
            300,
        );
        assert_eq!(read(&f).expect("a DHCP packet").gi, None);
        // And TFTP has no such field at all.
        let t = tftp(1, 50_000, TFTP, [10, 0, 0, 1], [10, 0, 0, 9]);
        assert_eq!(read(&t).expect("a TFTP packet").gi, None);
    }

    #[test]
    fn dhcpv6_counts_the_same_way() {
        let mut f = vec![0u8; 12];
        f.extend([0x86, 0xDD]);
        let mut ip = vec![0x60, 0, 0, 0];
        ip.extend([0, 16]); // payload length
        ip.extend([17, 64]); // UDP, hop limit
        ip.extend(
            [0x20, 0x01]
                .iter()
                .copied()
                .chain(std::iter::repeat_n(0, 14)),
        );
        ip.extend(
            [0x20, 0x01]
                .iter()
                .copied()
                .chain(std::iter::repeat_n(0, 13))
                .chain([9]),
        );
        ip.extend(DHCP6_CLIENT.to_be_bytes());
        ip.extend(DHCP6_SERVER.to_be_bytes());
        ip.extend(16u16.to_be_bytes());
        ip.extend([0, 0]);
        ip.extend([0u8; 8]);
        f.extend(ip);
        let seen = read(&f).expect("a DHCPv6 packet");
        assert_eq!(seen.kind, Kind::ClientRequest);
        assert_eq!(seen.bytes, 8);
    }

    // A provisioning interface is very often a trunk, so a tag is the normal
    // case rather than the exception.
    #[test]
    fn a_vlan_tag_is_stepped_over() {
        let plain = v4(DHCP_SERVER, DHCP_SERVER, [10, 0, 0, 1], [10, 0, 0, 9], 40);
        let mut tagged = plain[..12].to_vec();
        tagged.extend([0x81, 0x00, 0x00, 0x65]); // 802.1Q, VLAN 101
        tagged.extend(&plain[12..]);
        assert_eq!(read(&tagged).expect("still DHCP").kind, Kind::ClientRequest);

        // And a wholesale hand-off arrives with two.
        let mut double = plain[..12].to_vec();
        double.extend([0x88, 0xA8, 0x00, 0x65]); // 802.1ad outer
        double.extend([0x81, 0x00, 0x00, 0x0A]); // 802.1Q inner
        double.extend(&plain[12..]);
        assert_eq!(read(&double).expect("still DHCP").kind, Kind::ClientRequest);
    }

    #[test]
    fn everything_else_on_the_wire_is_ignored() {
        // Not UDP.
        let mut tcp = v4(DHCP_SERVER, DHCP_SERVER, [10, 0, 0, 1], [10, 0, 0, 9], 40);
        tcp[14 + 9] = 6;
        assert!(read(&tcp).is_none());
        // UDP, but nothing to do with provisioning.
        assert!(read(&v4(53, 53, [10, 0, 0, 1], [10, 0, 0, 9], 40)).is_none());
        // Not IP at all: ARP.
        let mut arp = vec![0u8; 12];
        arp.extend([0x08, 0x06]);
        arp.extend([0u8; 28]);
        assert!(read(&arp).is_none());
    }

    // A capture is the one input in this repository that arrives from outside
    // the plant entirely: anyone who can put a frame on the wire can put
    // anything they like in it. Every one of these must be None, and none of
    // them may panic in a process that is supposed to still be watching an
    // hour later.
    #[test]
    fn a_truncated_or_lying_frame_is_refused_rather_than_panicking() {
        let full = v4(DHCP_SERVER, DHCP_SERVER, [10, 0, 0, 1], [10, 0, 0, 9], 40);
        for cut in 0..full.len() {
            let _ = read(&full[..cut]); // must not panic
        }
        assert!(read(&[]).is_none());

        // An IPv4 header claiming a length below the twenty bytes it must
        // have. Trusting it would slice backwards.
        let mut short_ihl = full.clone();
        short_ihl[14] = 0x43;
        assert!(read(&short_ihl).is_none());

        // A UDP length below its own header.
        let mut short_udp = full.clone();
        short_udp[14 + 20 + 4] = 0;
        short_udp[14 + 20 + 5] = 4;
        assert!(read(&short_udp).is_none());

        // A frame claiming twenty VLAN tags is not a frame.
        let mut many = full[..12].to_vec();
        for _ in 0..20 {
            many.extend([0x81, 0x00, 0x00, 0x65]);
        }
        many.extend(&full[12..]);
        assert!(read(&many).is_none(), "the tag walk is bounded");
    }

    // A fragment that is not the first carries no UDP header. Counting one
    // would count half of something already counted.
    #[test]
    fn a_later_fragment_is_not_counted_again() {
        let mut f = v4(DHCP_SERVER, DHCP_SERVER, [10, 0, 0, 1], [10, 0, 0, 9], 40);
        f[14 + 6] = 0x00;
        f[14 + 7] = 0x20; // fragment offset 32 eight-octet units
        assert!(read(&f).is_none());
    }

    // An IPv6 extension header claiming a length of zero would walk the
    // header chain for ever on a crafted frame.
    #[test]
    fn an_ipv6_header_chain_cannot_loop_for_ever() {
        let mut f = vec![0u8; 12];
        f.extend([0x86, 0xDD]);
        let mut ip = vec![0x60, 0, 0, 0, 0, 64, 0, 64]; // next header 0: hop-by-hop
        ip.extend([0u8; 32]); // the two addresses
        for _ in 0..40 {
            ip.extend([0, 0]); // next header 0 again, length 0
            ip.extend([0u8; 6]);
        }
        f.extend(ip);
        let _ = read(&f); // must return, and must not panic
    }

    #[test]
    fn the_ports_say_whether_and_the_message_says_which_way() {
        // Whether.
        assert_eq!(classify(41_234, 69, b"\x00\x01"), Some(Kind::TftpRequest));
        assert_eq!(classify(69, 41_234, b"\x00\x03"), Some(Kind::TftpReply));
        assert_eq!(classify(53, 53, &[1]), None, "DNS is not provisioning");
        assert_eq!(classify(67, 5000, &[1]), None, "nor is 67 to anywhere");

        // Which way, on the pair of ports a relay uses for both.
        assert_eq!(classify(67, 67, &[1]), Some(Kind::ClientRequest));
        assert_eq!(classify(67, 67, &[2]), Some(Kind::ServerReply));
        assert_eq!(classify(68, 67, &[1]), Some(Kind::ClientRequest));
        assert_eq!(classify(67, 68, &[2]), Some(Kind::ServerReply));
    }
}
