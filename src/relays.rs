// Copyright MMQR Development
//! What each relay interface is doing, and how well it is being answered.
//!
//! A plant is not one thing. One CMTS carries several thousand modems and
//! should never be silent for five minutes; another carries forty and is
//! properly silent for an hour at a time. A single threshold over the whole
//! interface is wrong for both of them: set for the busy one it cries wolf
//! about the quiet one every night, and set for the quiet one it says nothing
//! for an hour after the busy one falls over.
//!
//! So everything here is per gi-address. That is the field the relay stamps
//! on a request and the field the server picks a pool from; it names one CMTS
//! interface, which is the thing that goes quiet and the thing somebody drives
//! out to look at.
//!
//! # Answered, and how fast
//!
//! Counting replies is not the same as knowing requests were answered. Two
//! thousand of each in a window is a plant answering everything in four
//! milliseconds, or one answering half of them twice, four seconds late.
//!
//! Both sides of the conversation cross this interface, so the difference is
//! measurable rather than inferred: a request and its answer carry the same
//! transaction id, and the gap between them is the server's response time as
//! the CMTS experiences it.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// How long an unanswered request is remembered before it is written off.
///
/// A modem retries a DISCOVER after a few seconds, so a reply arriving later
/// than this answered a request nobody is still waiting on. Bounded mostly so
/// the table cannot grow without limit on a plant where nothing is answered
/// at all, which is exactly when this program has the most to do.
const PENDING_FOR_MS: u64 = 30_000;

/// The most requests awaiting an answer at once.
///
/// A cap rather than a guess: 20,000 modems all retrying at the same instant
/// is a power event, and it must not turn the monitor into the second
/// casualty of one.
const MAX_PENDING: usize = 50_000;

/// One CMTS interface, as the wire shows it.
#[derive(Clone, Debug, Default)]
pub struct Relay {
    pub requests: u64,
    pub replies: u64,
    pub tftp_requests: u64,
    pub tftp_sends: u64,

    /// When a request was last seen from here. This, not a count, is what
    /// says whether the interface has gone quiet: the interfaces have
    /// different idea of normal and the same window cannot serve both.
    pub last_request: Option<u64>,
    pub last_reply: Option<u64>,
    pub first_seen: u64,

    /// The longest run of seconds between one request and the next.
    ///
    /// What an idle threshold has to be bigger than. Measured rather than
    /// assumed, which is what `--adaptation` is for.
    pub longest_gap: u64,

    /// Requests that got an answer, and how long they waited.
    pub answered: u64,
    answer_ms_total: u64,
    pub answer_ms_worst: u64,
}

impl Relay {
    /// Mean answer time in milliseconds, or None when nothing was answered.
    #[must_use]
    pub fn answer_ms_mean(&self) -> Option<u64> {
        (self.answered > 0).then(|| self.answer_ms_total / self.answered)
    }

    /// Seconds since a request last arrived, or None if none ever has.
    #[must_use]
    pub fn idle_for(&self, now: u64) -> Option<u64> {
        self.last_request.map(|t| now.saturating_sub(t))
    }

    /// Everything counted here, for deciding whether the row is worth a line.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.requests + self.replies + self.tftp_requests + self.tftp_sends
    }
}

/// Every relay interface seen, and the requests still waiting for an answer.
#[derive(Debug, Default)]
pub struct Relays {
    by_gi: BTreeMap<Ipv4Addr, Relay>,
    /// A row for everything with no gi-address: direct DHCP, and all TFTP,
    /// which carries no such field. Kept apart rather than folded into one of
    /// the relays, which would attribute a modem's config fetch to whichever
    /// interface happened to sort first.
    unrelayed: Relay,
    pending: BTreeMap<u32, Pending>,
    /// When the pending table was last swept.
    ///
    /// Sweeping on every request walks the whole table on every packet, which
    /// is quadratic in how many requests are outstanding -- and the number
    /// outstanding is largest exactly when the plant is in trouble and this
    /// program has the most to do. The test that fills the table found it: it
    /// took forty-seven seconds.
    swept_ms: u64,
}

/// How often the pending table is swept.
///
/// Once a second. A reply arriving a second after its request is timed against
/// it either way; what this bounds is how long a dead entry occupies memory,
/// not how accurate an answer time is.
const SWEEP_EVERY_MS: u64 = 1_000;

#[derive(Clone, Copy, Debug)]
struct Pending {
    at_ms: u64,
    gi: Option<Ipv4Addr>,
}

impl Relays {
    /// Records a client request.
    pub fn request(&mut self, gi: Option<Ipv4Addr>, xid: Option<u32>, now: u64, now_ms: u64) {
        let r = self.entry(gi, now);
        r.requests += 1;
        if let Some(last) = r.last_request {
            r.longest_gap = r.longest_gap.max(now.saturating_sub(last));
        }
        r.last_request = Some(now);

        if let Some(x) = xid {
            self.expire_pending(now_ms);
            if self.pending.len() < MAX_PENDING {
                // A retry replaces the first attempt rather than being
                // ignored: what a modem is waiting on is the LAST one it sent,
                // and timing from the first would report the retry interval as
                // the server's response time.
                self.pending.insert(x, Pending { at_ms: now_ms, gi });
            }
        }
    }

    /// Records a server reply, and times it against the request it answers.
    pub fn reply(&mut self, gi: Option<Ipv4Addr>, xid: Option<u32>, now: u64, now_ms: u64) {
        // A reply is attributed to the relay the REQUEST came through when
        // one is known. The reply's own gi-address is usually the same, but
        // on a direct answer to a client there is none, and that answer still
        // belongs to the interface that asked.
        let asked = xid.and_then(|x| self.pending.remove(&x));
        let owner = asked.and_then(|p| p.gi).or(gi);

        let r = self.entry(owner, now);
        r.replies += 1;
        r.last_reply = Some(now);
        if let Some(p) = asked {
            let took = now_ms.saturating_sub(p.at_ms);
            r.answered += 1;
            r.answer_ms_total += took;
            r.answer_ms_worst = r.answer_ms_worst.max(took);
        }
    }

    /// Records a TFTP read request.
    ///
    /// TFTP carries no gi-address, so these land under the unrelayed row. A
    /// plant's TFTP is far quieter than its DHCP in any case -- the equipment
    /// behind a modem never touches it, so a config fetch happens once when a
    /// modem boots and not again.
    pub fn tftp_request(&mut self, now: u64) {
        let r = self.entry(None, now);
        r.tftp_requests += 1;
    }

    pub fn tftp_send(&mut self, now: u64) {
        let r = self.entry(None, now);
        r.tftp_sends += 1;
    }

    fn entry(&mut self, gi: Option<Ipv4Addr>, now: u64) -> &mut Relay {
        if let Some(g) = gi {
            return self.by_gi.entry(g).or_insert_with(|| Relay {
                first_seen: now,
                ..Relay::default()
            });
        }
        if self.unrelayed.first_seen == 0 {
            self.unrelayed.first_seen = now;
        }
        &mut self.unrelayed
    }

    fn expire_pending(&mut self, now_ms: u64) {
        if now_ms.saturating_sub(self.swept_ms) < SWEEP_EVERY_MS {
            return;
        }
        self.swept_ms = now_ms;
        let cutoff = now_ms.saturating_sub(PENDING_FOR_MS);
        self.pending.retain(|_, p| p.at_ms > cutoff);
    }

    /// The relays, in address order.
    ///
    /// Address order, not busiest first: this list is read to compare one
    /// interface against another and against yesterday, and an order that
    /// moves when the traffic moves cannot be compared with anything.
    #[must_use]
    pub fn each(&self) -> Vec<(Ipv4Addr, &Relay)> {
        self.by_gi.iter().map(|(g, r)| (*g, r)).collect()
    }

    /// Everything with no gi-address, which is where TFTP lives.
    #[must_use]
    pub const fn unrelayed(&self) -> &Relay {
        &self.unrelayed
    }

    /// How many requests are still waiting for an answer.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A gi-address, as the packet reader hands one over.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "callers pass this straight through as an Option, which is what a packet gives"
    )]
    fn gi(n: u8) -> Option<Ipv4Addr> {
        Some(Ipv4Addr::new(10, 100, 0, n))
    }

    #[test]
    fn each_relay_is_counted_on_its_own() {
        let mut r = Relays::default();
        r.request(gi(1), Some(1), 1000, 1_000_000);
        r.request(gi(1), Some(2), 1001, 1_001_000);
        r.request(gi(2), Some(3), 1002, 1_002_000);

        let seen = r.each();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].1.requests, 2, "10.100.0.1");
        assert_eq!(seen[1].1.requests, 1, "10.100.0.2");
    }

    // Counting replies is not knowing requests were answered. This is the
    // difference between "two thousand replies" and "two thousand requests
    // answered, in four milliseconds".
    #[test]
    fn an_answer_is_timed_against_the_request_it_answers() {
        let mut r = Relays::default();
        r.request(gi(1), Some(0xAAAA), 1000, 1_000_000);
        r.reply(gi(1), Some(0xAAAA), 1000, 1_000_004);
        r.request(gi(1), Some(0xBBBB), 1001, 1_001_000);
        r.reply(gi(1), Some(0xBBBB), 1001, 1_001_120);

        let (_, relay) = r.each()[0];
        assert_eq!(relay.answered, 2);
        assert_eq!(relay.answer_ms_mean(), Some(62), "(4 + 120) / 2");
        assert_eq!(relay.answer_ms_worst, 120);
        assert_eq!(r.waiting(), 0, "both were answered");
    }

    // A reply with no request behind it is still a reply, and must not be
    // counted as one that was answered quickly.
    #[test]
    fn a_reply_to_nothing_is_counted_but_not_timed() {
        let mut r = Relays::default();
        r.reply(gi(1), Some(0xCCCC), 1000, 1_000_000);
        let (_, relay) = r.each()[0];
        assert_eq!(relay.replies, 1);
        assert_eq!(relay.answered, 0);
        assert_eq!(relay.answer_ms_mean(), None);
    }

    // A reply belongs to the interface that ASKED. On a direct answer to a
    // client there is no gi-address on the reply at all, and that answer is
    // still the relay's.
    #[test]
    fn a_reply_is_credited_to_the_relay_that_asked() {
        let mut r = Relays::default();
        r.request(gi(7), Some(0xDDDD), 1000, 1_000_000);
        r.reply(None, Some(0xDDDD), 1000, 1_000_010);
        let seen = r.each();
        assert_eq!(seen.len(), 1, "no second row for the answer");
        assert_eq!(seen[0].1.replies, 1);
        assert_eq!(seen[0].1.answered, 1);
    }

    // What an idle threshold has to be bigger than, measured rather than
    // assumed.
    #[test]
    fn the_longest_gap_between_requests_is_remembered() {
        let mut r = Relays::default();
        for at in [1000u64, 1005, 1010, 1400, 1405] {
            r.request(gi(1), None, at, at * 1000);
        }
        assert_eq!(r.each()[0].1.longest_gap, 390);
        assert_eq!(r.each()[0].1.idle_for(1500), Some(95));
    }

    // A modem retries. What it is waiting on is the last one it sent, and
    // timing from the first would report the retry interval as the server's
    // response time.
    #[test]
    fn a_retry_replaces_the_attempt_it_repeats() {
        let mut r = Relays::default();
        r.request(gi(1), Some(0xEEEE), 1000, 1_000_000);
        r.request(gi(1), Some(0xEEEE), 1004, 1_004_000);
        r.reply(gi(1), Some(0xEEEE), 1004, 1_004_030);
        let (_, relay) = r.each()[0];
        assert_eq!(relay.answer_ms_worst, 30, "not 4030");
    }

    // Twenty thousand modems retrying at once is a power event. It must not
    // make the monitor the second casualty.
    #[test]
    fn nothing_answered_does_not_grow_without_limit() {
        let mut r = Relays::default();
        let began = std::time::Instant::now();
        for i in 0..(u32::try_from(MAX_PENDING).unwrap_or(u32::MAX) + 5_000) {
            r.request(gi(1), Some(i), 1000, 1_000_000);
        }
        assert!(r.waiting() <= MAX_PENDING, "kept {}", r.waiting());

        // And it must not take a measurable amount of time to do it. This
        // assertion is here because the first version of this test took
        // FORTY-SEVEN SECONDS: the pending table was swept on every request,
        // which walks the whole thing per packet, and the number outstanding
        // is largest exactly when the plant is in trouble.
        let took = began.elapsed();
        assert!(
            took < std::time::Duration::from_secs(2),
            "55,000 unanswered requests took {took:?}"
        );
    }

    // A reply arriving half a minute late answered a request nobody is
    // waiting on any more.
    #[test]
    fn a_very_late_reply_is_not_timed_against_a_forgotten_request() {
        let mut r = Relays::default();
        r.request(gi(1), Some(0xF00D), 1000, 1_000_000);
        // Another request moves the clock on, which is what expires the first.
        r.request(gi(1), Some(0xBEEF), 1100, 1_100_000);
        r.reply(gi(1), Some(0xF00D), 1100, 1_100_000);
        let (_, relay) = r.each()[0];
        assert_eq!(relay.replies, 1);
        assert_eq!(relay.answered, 0, "the request had been written off");
    }

    // TFTP has no gi-address. Folding it into a relay would attribute a
    // modem's config fetch to whichever interface happened to sort first.
    #[test]
    fn tftp_is_kept_apart_from_the_relays() {
        let mut r = Relays::default();
        r.request(gi(1), None, 1000, 1_000_000);
        r.tftp_request(1000);
        r.tftp_send(1000);
        assert_eq!(r.each().len(), 1);
        assert_eq!(r.each()[0].1.tftp_requests, 0);
        assert_eq!(r.unrelayed().tftp_requests, 1);
        assert_eq!(r.unrelayed().tftp_sends, 1);
    }
}
