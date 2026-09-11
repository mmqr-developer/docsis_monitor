// Copyright MMQR Development
//! What has been seen lately, and where it was going.
//!
//! A sliding window of one-second buckets. A judgement is made over the last
//! `window` seconds, so the counts have to be able to forget: a total since
//! start-up says nothing about whether the plant is working NOW, which is the
//! only question this program is asked.
//!
//! Buckets rather than timestamps per packet. A busy plant is thousands of
//! packets a minute and this runs for months; a list that grows with traffic
//! is a monitor that eventually becomes the outage.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use crate::packet::Kind;

/// Who was talking to whom, and through which relay interface.
///
/// The destination alone was not enough. On a relayed plant every request has
/// the same destination -- the server -- so a list keyed on it had one useful
/// row and nothing to compare. Both ends and the gi-address is what names the
/// thing that has gone quiet: the server sees requests arrive from one relay
/// carrying a dozen gi-addresses, and it is a gi-address that stops, not a
/// relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Flow {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// The gi-address, on a `DHCPv4` packet that was relayed. None on
    /// anything else, including TFTP, which has no such field.
    pub gi: Option<Ipv4Addr>,
}

/// One second's worth.
#[derive(Clone, Debug, Default)]
struct Bucket {
    at: u64,
    counts: [u64; 4],
}

/// The sliding window, plus who the traffic was for.
#[derive(Debug)]
pub struct Counters {
    window: u64,
    buckets: Vec<Bucket>,
    /// Packets per flow, over the same window.
    ///
    /// This is what turns "requests have stopped" into something somebody can
    /// act on: on a plant with four CMTS interfaces, three still talking and
    /// one silent names the one to go and look at. Kept as a map because a
    /// plant has tens of relay interfaces, not thousands.
    flows: BTreeMap<Flow, Dest>,
    /// Totals since the program started, for the log line.
    total: [u64; 4],
}

/// One flow's share.
#[derive(Clone, Copy, Debug, Default)]
pub struct Dest {
    pub counts: [u64; 4],
    /// When this flow was last seen, so one that has gone quiet can be named
    /// rather than silently dropped off the list.
    pub last: u64,
}

impl Dest {
    /// Everything counted on this flow.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts.iter().sum()
    }
}

/// A window's worth of counts, ready to be judged or logged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Window {
    pub requests: u64,
    pub replies: u64,
    pub tftp_reads: u64,
    pub tftp_sends: u64,
}

impl Window {
    /// The fraction of client requests that were answered.
    ///
    /// Can exceed 1: a server retransmits an offer a client did not take, and
    /// a relay can duplicate. That is not an error and is not clamped --
    /// clamping would hide a plant answering four times over, which is its own
    /// kind of broken.
    #[must_use]
    pub fn answered(self) -> f64 {
        if self.requests == 0 {
            return 0.0;
        }
        // Exact for every count this will ever hold: a plant would need 2^53
        // packets in one window to lose a digit here.
        #[allow(clippy::cast_precision_loss, reason = "counts never reach 2^53")]
        {
            self.replies as f64 / self.requests as f64
        }
    }
}

const fn slot(k: Kind) -> usize {
    match k {
        Kind::ClientRequest => 0,
        Kind::ServerReply => 1,
        Kind::TftpRequest => 2,
        Kind::TftpReply => 3,
    }
}

impl Counters {
    #[must_use]
    pub fn new(window: u64) -> Self {
        Self {
            window: window.max(1),
            buckets: Vec::new(),
            flows: BTreeMap::new(),
            total: [0; 4],
        }
    }

    /// Records one packet, at a whole second.
    pub fn add(&mut self, kind: Kind, flow: Flow, now: u64) {
        self.expire(now);
        let i = slot(kind);
        match self.buckets.last_mut() {
            Some(b) if b.at == now => b.counts[i] += 1,
            _ => {
                let mut b = Bucket {
                    at: now,
                    counts: [0; 4],
                };
                b.counts[i] = 1;
                self.buckets.push(b);
            }
        }
        let d = self.flows.entry(flow).or_default();
        d.counts[i] += 1;
        d.last = now;
        self.total[i] += 1;
    }

    /// Drops everything older than the window.
    ///
    /// Called on the way in and again before reading, because a plant that
    /// goes completely silent adds nothing -- and a window that only expires
    /// on `add` would keep reporting the last packets before the silence for
    /// ever, which is the exact case this program exists to notice.
    pub fn expire(&mut self, now: u64) {
        let cutoff = now.saturating_sub(self.window);
        self.buckets.retain(|b| b.at > cutoff);
        self.flows.retain(|_, d| d.last > cutoff);
    }

    /// What the window holds, as of `now`.
    pub fn window(&mut self, now: u64) -> Window {
        self.expire(now);
        let mut sum = [0u64; 4];
        for b in &self.buckets {
            for (into, from) in sum.iter_mut().zip(b.counts) {
                *into += from;
            }
        }
        Window {
            requests: sum[0],
            replies: sum[1],
            tftp_reads: sum[2],
            tftp_sends: sum[3],
        }
    }

    /// Everything seen since the program started.
    #[must_use]
    pub fn total(&self) -> Window {
        Window {
            requests: self.total[0],
            replies: self.total[1],
            tftp_reads: self.total[2],
            tftp_sends: self.total[3],
        }
    }

    /// The flows in the window, busiest first.
    ///
    /// Busiest first because the interesting one is usually at an end: the
    /// interface carrying the plant, or the one that has dropped to nothing.
    pub fn by_flow(&mut self, now: u64) -> Vec<(Flow, Dest)> {
        self.expire(now);
        let mut out: Vec<(Flow, Dest)> = self.flows.iter().map(|(k, v)| (*k, *v)).collect();
        out.sort_by(|a, b| b.1.total().cmp(&a.1.total()).then(a.0.cmp(&b.0)));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    /// A request flowing from a relay to the server, through one gi-address.
    fn to_server(from: u8, gi: u8) -> Flow {
        Flow {
            src: ip(from),
            dst: ip(9),
            gi: Some(Ipv4Addr::new(10, 100, 0, gi)),
        }
    }

    #[test]
    fn a_packet_lands_in_the_window_and_in_the_total() {
        let mut c = Counters::new(300);
        c.add(Kind::ClientRequest, to_server(1, 1), 1000);
        c.add(Kind::ServerReply, to_server(2, 2), 1000);
        assert_eq!(
            c.window(1000),
            Window {
                requests: 1,
                replies: 1,
                ..Window::default()
            }
        );
        assert_eq!(c.total().requests, 1);
    }

    // The whole point of a window. A total since start-up says nothing about
    // whether the plant is working now.
    #[test]
    fn what_falls_out_of_the_window_stops_counting() {
        let mut c = Counters::new(60);
        c.add(Kind::ClientRequest, to_server(1, 1), 1000);
        assert_eq!(c.window(1030).requests, 1, "still inside the window");
        assert_eq!(c.window(1100).requests, 0, "past it");
        assert_eq!(c.total().requests, 1, "the total does not forget");
    }

    // A plant that goes completely silent adds nothing, so a window that only
    // expired on the way IN would report the last packets before the silence
    // for ever -- which is the exact case this program exists to notice.
    #[test]
    fn silence_empties_the_window_without_a_single_packet() {
        let mut c = Counters::new(60);
        for t in 0..10 {
            c.add(Kind::ClientRequest, to_server(1, 1), 1000 + t);
        }
        assert_eq!(c.window(1009).requests, 10);
        assert_eq!(c.window(2000).requests, 0, "nothing arrived to expire it");
        assert!(c.by_flow(2000).is_empty());
    }

    #[test]
    fn the_answered_fraction_is_replies_over_requests() {
        let w = Window {
            requests: 4,
            replies: 3,
            ..Window::default()
        };
        assert!((w.answered() - 0.75).abs() < 1e-9);
        // Nothing asked is not "nothing answered": that is the other alarm's
        // business, and a ratio of 0/0 would trip this one on a quiet plant.
        assert!((Window::default().answered() - 0.0).abs() < 1e-9);
    }

    // A server retransmits, and a relay duplicates. More replies than
    // requests is not an error, and clamping it would hide a plant answering
    // four times over, which is its own kind of broken.
    #[test]
    fn more_replies_than_requests_is_reported_not_clamped() {
        let w = Window {
            requests: 2,
            replies: 8,
            ..Window::default()
        };
        assert!((w.answered() - 4.0).abs() < 1e-9);
    }

    // On a plant with four relays, three talking and one silent names the one
    // to go and look at. That is what makes "requests have stopped" into
    // something somebody can act on.
    #[test]
    fn flows_are_listed_busiest_first() {
        let mut c = Counters::new(300);
        for _ in 0..3 {
            c.add(Kind::ClientRequest, to_server(1, 1), 1000);
        }
        for _ in 0..9 {
            c.add(Kind::ClientRequest, to_server(2, 2), 1000);
        }
        c.add(Kind::ClientRequest, to_server(3, 3), 1000);
        let got: Vec<Flow> = c.by_flow(1000).into_iter().map(|(f, _)| f).collect();
        assert_eq!(got, vec![to_server(2, 2), to_server(1, 1), to_server(3, 3)]);
    }

    #[test]
    fn a_flow_that_goes_quiet_leaves_the_list() {
        let mut c = Counters::new(60);
        c.add(Kind::ClientRequest, to_server(1, 1), 1000);
        c.add(Kind::ClientRequest, to_server(2, 2), 1050);
        let still: Vec<Flow> = c.by_flow(1080).into_iter().map(|(f, _)| f).collect();
        assert_eq!(
            still,
            vec![to_server(2, 2)],
            "the flow from 10.0.0.1 has not been seen for 80s"
        );
    }

    // A monitor runs for months. A structure that grows with traffic is one
    // that eventually becomes the outage it was watching for.
    #[test]
    fn a_long_quiet_run_does_not_accumulate() {
        let mut c = Counters::new(60);
        for t in 0..5_000 {
            c.add(Kind::ClientRequest, to_server(1, 1), 1000 + t);
        }
        assert!(
            c.buckets.len() <= 61,
            "kept {} buckets for a 60s window",
            c.buckets.len()
        );
    }
}
