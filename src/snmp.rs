// Copyright MMQR Development
//! Sending an `SNMPv2c` trap.
//!
//! One UDP datagram, BER-encoded, built here rather than taken from a crate.
//! An `SNMPv2c` trap is a small and completely specified structure -- RFC 3416
//! section 4.2.6 -- and the encoding is the part a test can check byte for
//! byte on this machine, with no network and no receiver. A crate would move
//! that check to somewhere it cannot be run.
//!
//! # What is in it
//!
//! Two varbinds are mandatory and come first, in this order, or a receiver
//! rejects the whole thing:
//!
//! * `sysUpTime.0` — a `TimeTicks`, hundredths of a second.
//! * `snmpTrapOID.0` — the OID naming which trap this is.
//!
//! After them, anything. This sends the interface, the state, and the counts
//! the judgement was made from, because a trap that says "something is wrong"
//! and makes somebody log in to find out what is a trap that gets ignored.
//!
//! # What it is not
//!
//! It is not authentication. The community string is a password sent in clear
//! text, which is what `SNMPv2c` is; it is here because receivers demand one.
//! Anything that can read the wire can read it, and anything that can write
//! to the wire can forge the trap. That is a property of the protocol the
//! network management platform speaks, not a decision made here.

use std::io;
use std::net::{ToSocketAddrs, UdpSocket};

use crate::config::Target;

/// The private enterprise arc these traps live under.
///
/// 1.3.6.1.4.1 is `enterprises`; 99999 is a placeholder for whoever installs
/// this. It is deliberately NOT configurable: an OID that varies per install
/// is an OID no receiver can be configured for, and the trap's meaning is
/// carried by the varbinds rather than by the number.
const ENTERPRISE: &[u64] = &[1, 3, 6, 1, 4, 1, 99_999];

/// `sysUpTime`.0 and `snmpTrapOID`.0, the two a v2c trap must open with.
const SYS_UPTIME: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];
const TRAP_OID: &[u64] = &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0];

/// One thing a trap says.
#[derive(Clone, Debug)]
pub enum Value {
    Str(String),
    Count(u64),
    Oid(Vec<u64>),
    Ticks(u64),
}

/// The trap to send.
#[derive(Clone, Debug)]
pub struct Trap {
    /// Hundredths of a second this program has been running.
    pub uptime_ticks: u64,
    /// Which trap: the enterprise arc plus one number.
    pub which: u64,
    /// Everything after the two mandatory varbinds.
    pub bindings: Vec<(Vec<u64>, Value)>,
}

impl Trap {
    /// The OID naming this trap, which is what a receiver keys its rules on.
    #[must_use]
    pub fn oid(&self) -> Vec<u64> {
        let mut v = ENTERPRISE.to_vec();
        v.push(self.which);
        v
    }

    /// An OID under this program's arc, for a varbind.
    #[must_use]
    pub fn field(n: u64) -> Vec<u64> {
        let mut v = ENTERPRISE.to_vec();
        v.extend_from_slice(&[1, n]);
        v
    }
}

/// Encodes the whole datagram.
#[must_use]
pub fn encode(community: &str, t: &Trap) -> Vec<u8> {
    let mut varbinds = Vec::new();
    varbinds.extend(varbind(SYS_UPTIME, &Value::Ticks(t.uptime_ticks)));
    varbinds.extend(varbind(TRAP_OID, &Value::Oid(t.oid())));
    for (oid, v) in &t.bindings {
        varbinds.extend(varbind(oid, v));
    }
    let varbind_list = tlv(0x30, &varbinds);

    let mut pdu = Vec::new();
    // request-id, error-status, error-index. A trap is not answered, so the
    // request-id is only ever a duplicate detector; it is derived from the
    // uptime so two traps in the same hundredth of a second are the only ones
    // that can collide, and those are the same event anyway.
    pdu.extend(integer(
        i64::try_from(t.uptime_ticks & 0x7FFF_FFFF).unwrap_or(0),
    ));
    pdu.extend(integer(0));
    pdu.extend(integer(0));
    pdu.extend(varbind_list);
    // 0xA7 is context-specific constructed 7: SNMPv2-Trap-PDU.
    let pdu = tlv(0xA7, &pdu);

    let mut msg = Vec::new();
    msg.extend(integer(1)); // version 1 means SNMPv2c
    msg.extend(octet_string(community.as_bytes()));
    msg.extend(pdu);
    tlv(0x30, &msg)
}

/// Sends a trap to one receiver.
///
/// UDP, so this reports that the datagram was HANDED OVER and nothing more. A
/// trap that never arrives leaves no error here; that is what SNMP traps are,
/// and it is why the same finding is written to the log whether a trap was
/// sent or not.
pub fn send(target: &Target, t: &Trap) -> io::Result<()> {
    let datagram = encode(&target.community, t);
    let to = (target.host.as_str(), target.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::other(format!("{} resolves to no address", target.host)))?;
    // Bound to whichever family the target turned out to be, and to no
    // particular address: this program never receives on this socket.
    let bind = if to.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind)?;
    sock.send_to(&datagram, to)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// BER
// ---------------------------------------------------------------------------

/// A tag, a length and a body.
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(length(body.len()));
    out.extend_from_slice(body);
    out
}

/// BER length: short form under 128, long form above.
///
/// The long form is a count of length bytes with the high bit set, then the
/// length itself big-endian with no leading zeroes. A trap carrying a few
/// hundred bytes of varbinds needs it, which is why this is not the two-line
/// short-form-only version.
fn length(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![u8::try_from(n).unwrap_or(0x7F)];
    }
    let be = n.to_be_bytes();
    let first = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
    let bytes = &be[first..];
    let mut out = vec![0x80 | u8::try_from(bytes.len()).unwrap_or(1)];
    out.extend_from_slice(bytes);
    out
}

/// A signed integer, in the fewest bytes two's complement allows.
fn integer(v: i64) -> Vec<u8> {
    let be = v.to_be_bytes();
    let mut at = 0;
    // Strip leading 0x00 before a positive byte and 0xFF before a negative
    // one; stop when doing so would change the sign, which is the whole rule.
    while at < 7
        && ((be[at] == 0 && be[at + 1] & 0x80 == 0) || (be[at] == 0xFF && be[at + 1] & 0x80 != 0))
    {
        at += 1;
    }
    tlv(0x02, &be[at..])
}

/// An unsigned 32-bit counter or gauge, which BER still encodes as a
/// non-negative integer -- so a value with the top bit set needs a leading
/// zero or a receiver reads it as negative.
fn unsigned(tag: u8, v: u64) -> Vec<u8> {
    let v = u32::try_from(v).unwrap_or(u32::MAX);
    let be = v.to_be_bytes();
    let first = be.iter().position(|b| *b != 0).unwrap_or(3);
    let mut body = Vec::new();
    if be[first] & 0x80 != 0 {
        body.push(0);
    }
    body.extend_from_slice(&be[first..]);
    tlv(tag, &body)
}

fn octet_string(b: &[u8]) -> Vec<u8> {
    tlv(0x04, b)
}

/// An object identifier.
///
/// The first two arcs are packed into one byte as `40 * a + b`, and every arc
/// after that is base-128 with the high bit set on all but the last byte.
fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut body = Vec::new();
    let a = arcs.first().copied().unwrap_or(0);
    let b = arcs.get(1).copied().unwrap_or(0);
    body.extend(base128(a * 40 + b));
    for arc in arcs.iter().skip(2) {
        body.extend(base128(*arc));
    }
    tlv(0x06, &body)
}

fn base128(mut v: u64) -> Vec<u8> {
    let mut out = vec![u8::try_from(v & 0x7F).unwrap_or(0)];
    v >>= 7;
    while v > 0 {
        out.insert(0, u8::try_from(v & 0x7F).unwrap_or(0) | 0x80);
        v >>= 7;
    }
    out
}

/// One varbind: a sequence of an OID and its value.
fn varbind(name: &[u64], v: &Value) -> Vec<u8> {
    let mut body = oid(name);
    body.extend(match v {
        Value::Str(s) => octet_string(s.as_bytes()),
        // 0x41 is Counter32, 0x43 is TimeTicks: application tags 1 and 3.
        Value::Count(n) => unsigned(0x41, *n),
        Value::Ticks(n) => unsigned(0x43, *n),
        Value::Oid(o) => oid(o),
    });
    tlv(0x30, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trap() -> Trap {
        Trap {
            uptime_ticks: 12_345,
            which: 1,
            bindings: vec![
                (Trap::field(1), Value::Str("eth0".to_owned())),
                (Trap::field(2), Value::Count(0)),
            ],
        }
    }

    #[test]
    fn a_short_length_is_one_byte_and_a_long_one_says_how_many() {
        assert_eq!(length(0), vec![0x00]);
        assert_eq!(length(127), vec![0x7F]);
        assert_eq!(length(128), vec![0x81, 0x80]);
        assert_eq!(length(300), vec![0x82, 0x01, 0x2C]);
    }

    // The first two arcs share a byte, and everything above 127 is base-128.
    // 1.3.6.1.4.1.99999 exercises both.
    #[test]
    fn an_oid_packs_its_first_two_arcs_and_base128s_the_rest() {
        assert_eq!(oid(&[1, 3, 6, 1]), vec![0x06, 0x03, 0x2B, 0x06, 0x01]);
        let big = oid(&[1, 3, 6, 1, 4, 1, 99_999]);
        assert_eq!(
            big,
            vec![0x06, 0x08, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F]
        );
    }

    #[test]
    fn an_integer_uses_the_fewest_bytes_that_keep_its_sign() {
        assert_eq!(integer(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(integer(127), vec![0x02, 0x01, 0x7F]);
        assert_eq!(integer(128), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(integer(-1), vec![0x02, 0x01, 0xFF]);
        assert_eq!(integer(-129), vec![0x02, 0x02, 0xFF, 0x7F]);
    }

    // A Counter32 is unsigned, and BER integers are signed. Without the
    // leading zero a receiver reads 3 billion as a negative number.
    #[test]
    fn a_counter_with_its_top_bit_set_keeps_a_leading_zero() {
        assert_eq!(unsigned(0x41, 0), vec![0x41, 0x01, 0x00]);
        assert_eq!(unsigned(0x41, 200), vec![0x41, 0x02, 0x00, 0xC8]);
        assert_eq!(
            unsigned(0x41, 3_000_000_000),
            vec![0x41, 0x05, 0x00, 0xB2, 0xD0, 0x5E, 0x00]
        );
    }

    // The two mandatory varbinds come first and in this order, or a receiver
    // rejects the whole datagram. This is the assertion that catches somebody
    // adding a binding at the front.
    #[test]
    fn the_message_opens_the_way_a_v2c_trap_must() {
        let d = encode("public", &trap());
        assert_eq!(d[0], 0x30, "a sequence");
        // version 1 (meaning v2c), then the community.
        let after_len = 2 + usize::from(d[1] & 0x80 != 0) * usize::from(d[1] & 0x7F);
        assert_eq!(&d[after_len..after_len + 3], &[0x02, 0x01, 0x01]);
        assert!(
            d.windows(6).any(|w| w == b"public"),
            "the community is in the datagram"
        );
        assert!(
            d.windows(1).any(|w| w == [0xA7]),
            "the PDU is tagged SNMPv2-Trap"
        );
        // sysUpTime.0 then snmpTrapOID.0.
        let up = oid(SYS_UPTIME);
        let which = oid(TRAP_OID);
        let at_up = find(&d, &up).expect("sysUpTime.0 is in the datagram");
        let at_which = find(&d, &which).expect("snmpTrapOID.0 is in the datagram");
        assert!(at_up < at_which, "sysUpTime.0 must come first");
    }

    #[test]
    fn the_trap_oid_is_this_programs_arc_plus_its_number() {
        assert_eq!(trap().oid(), vec![1, 3, 6, 1, 4, 1, 99_999, 1]);
        assert_eq!(Trap::field(2), vec![1, 3, 6, 1, 4, 1, 99_999, 1, 2]);
    }

    // Nothing in a trap is trusted to be short. An interface name, a state
    // word and half a dozen counts go past 127 bytes easily, and a short-form
    // length there would produce a datagram no receiver can parse.
    #[test]
    fn a_trap_long_enough_to_need_a_long_length_still_encodes() {
        let mut t = trap();
        for i in 0..20 {
            t.bindings
                .push((Trap::field(i), Value::Str("a rather long value".to_owned())));
        }
        let d = encode("public", &t);
        assert!(d.len() > 300, "got {} bytes", d.len());
        assert_eq!(d[1] & 0x80, 0x80, "the outer length is in long form");
        // The outer length has to describe the rest exactly, or a receiver
        // stops reading in the middle.
        let n = usize::from(d[1] & 0x7F);
        let mut declared = 0usize;
        for b in &d[2..2 + n] {
            declared = declared * 256 + usize::from(*b);
        }
        assert_eq!(declared, d.len() - 2 - n);
    }

    // The datagram has to leave this process and arrive somewhere readable.
    // Everything above checks bytes this file produced against bytes this
    // file expects; this one puts it on a socket and takes it apart again
    // with a reader written from the other direction.
    //
    // It has also been read by tcpdump's own SNMP decoder, which printed the
    // trap OID and all eight varbinds -- including a Counter32 of three
    // billion, the value that comes out negative if the leading zero is
    // dropped.
    #[test]
    fn a_trap_goes_over_a_socket_and_comes_back_readable() {
        let listener = UdpSocket::bind("127.0.0.1:0").expect("a local socket");
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("a timeout");
        let at = listener.local_addr().expect("its address");

        let target = Target {
            host: at.ip().to_string(),
            port: at.port(),
            community: "s3cret".to_owned(),
        };
        let mut t = trap();
        t.bindings
            .push((Trap::field(6), Value::Count(3_000_000_000)));
        send(&target, &t).expect("the datagram is handed over");

        let mut buf = [0u8; 4096];
        let (n, _) = listener.recv_from(&mut buf).expect("it arrived");
        let got = &buf[..n];

        // Walk it as a receiver would: sequence, version, community, PDU.
        let (tag, body) = next(got).expect("a TLV");
        assert_eq!(tag, 0x30, "the message is a sequence");
        let (tag, version) = next(body).expect("the version");
        assert_eq!((tag, version), (0x02, [1].as_slice()), "v2c is version 1");
        let rest = &body[2 + version.len()..];
        let (tag, community) = next(rest).expect("the community");
        assert_eq!(tag, 0x04);
        assert_eq!(community, b"s3cret", "the community survived the wire");
        let rest = &rest[2 + community.len()..];
        let (tag, _) = next(rest).expect("the PDU");
        assert_eq!(tag, 0xA7, "an SNMPv2-Trap-PDU");

        // And the counter that needed a leading zero is still three billion.
        let wanted = unsigned(0x41, 3_000_000_000);
        assert!(
            find(got, &wanted).is_some(),
            "a Counter32 of three billion is not in the datagram as encoded"
        );
    }

    /// Reads one TLV: its tag and its body. Written from the receiver's side
    /// rather than reusing anything above, so a mistake shared by both is not
    /// a mistake this test agrees with.
    fn next(b: &[u8]) -> Option<(u8, &[u8])> {
        let tag = *b.first()?;
        let first = *b.get(1)?;
        let (len, at) = if first & 0x80 == 0 {
            (usize::from(first), 2)
        } else {
            let n = usize::from(first & 0x7F);
            let mut len = 0usize;
            for i in 0..n {
                len = len * 256 + usize::from(*b.get(2 + i)?);
            }
            (len, 2 + n)
        };
        Some((tag, b.get(at..at + len)?))
    }

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }
}
