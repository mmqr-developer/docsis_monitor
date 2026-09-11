// Copyright MMQR Development
//! Working out what "idle" means on a plant nobody has measured.
//!
//! An idle threshold is a claim about a CMTS interface: this one is never
//! silent for more than five minutes, that one is properly silent for an
//! hour. Guessing it produces one of two bad monitors -- one that cries wolf
//! about a quiet interface every night, or one that says nothing for an hour
//! after a busy one falls over.
//!
//! So `--adaptation 60` watches for an hour and then writes down what it saw:
//! for every interface that relayed anything, how many requests arrived, the
//! longest silence between two of them, and a threshold with room above that.
//! The output is a block that can be pasted into the configuration.
//!
//! # What it cannot do
//!
//! It sees one hour of one day. A plant is busiest in the evening and quietest
//! at four in the morning, and an hour at noon says nothing about either. The
//! suggestion is printed with the evidence beside it -- the count, the span,
//! the longest gap -- so somebody can see whether the window was long enough
//! to be worth anything, and it says so out loud when it was not.

use std::fmt::Write as _;
use std::net::Ipv4Addr;

use crate::relays::Relays;

/// What was measured for one interface, and what it suggests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Suggestion {
    pub gi: Ipv4Addr,
    pub requests: u64,
    /// Seconds between the first packet seen from here and the last.
    pub span: u64,
    pub longest_gap: u64,
    /// The suggested `idle_seconds`, or None when the window saw too little
    /// to say anything honest.
    pub idle_seconds: Option<u64>,
    /// Why, in one line, for the log.
    pub because: String,
}

/// The smallest threshold worth suggesting.
///
/// Below five minutes a threshold fires on one slow moment: a CMTS reloading
/// a line card, a switch converging, a burst of retries finishing. Nothing
/// useful is caught in that window that is not also caught at five minutes.
const FLOOR: u64 = 300;

/// The largest.
///
/// A day. An interface that can be silent for longer than that is one this
/// program cannot say anything useful about, and a threshold of a week reads
/// as monitoring while being none.
const CEILING: u64 = 86_400;

/// How much room a suggestion leaves above the worst gap seen.
///
/// Three times. Twice is too tight -- the longest gap in an hour is not the
/// longest gap in a week, and a threshold that fires on the second-worst
/// night is a threshold somebody turns off. Ten times would be so loose that
/// a real outage sits under it.
const HEADROOM: u64 = 3;

/// Turns what was watched into a suggestion per interface.
#[must_use]
pub fn suggest(relays: &Relays, watched_for: u64) -> Vec<Suggestion> {
    relays
        .each()
        .into_iter()
        .map(|(gi, r)| {
            let span = match (r.last_request, r.first_seen) {
                (Some(last), first) if last > first => last - first,
                _ => 0,
            };
            let (idle, because) = judge(r.requests, span, r.longest_gap, watched_for);
            Suggestion {
                gi,
                requests: r.requests,
                span,
                longest_gap: r.longest_gap,
                idle_seconds: idle,
                because,
            }
        })
        .collect()
}

/// The suggestion, and the sentence that justifies it.
fn judge(requests: u64, span: u64, longest_gap: u64, watched_for: u64) -> (Option<u64>, String) {
    // Nothing at all. There is no threshold for an interface that said
    // nothing: it may be dead, it may be idle, and this cannot tell which.
    if requests == 0 {
        return (
            None,
            "nothing arrived. Either this interface is idle or it is already \
             broken, and one hour of silence cannot tell the difference"
                .to_owned(),
        );
    }
    // One request is a data point, not an interval. There is no gap between
    // one thing and itself.
    if requests < 2 {
        return (
            None,
            format!(
                "only 1 request in {}. Watch for longer: a threshold needs at \
                 least two, to have a gap between them",
                minutes(watched_for)
            ),
        );
    }
    let suggested = (longest_gap * HEADROOM).clamp(FLOOR, CEILING);
    let because = if longest_gap * HEADROOM < FLOOR {
        // The floor, and WHY it applied. "Busy enough" was wrong here and the
        // live run said so: an interface silent for a minute and a half is
        // not busy, it is one whose silence still fits under five minutes
        // once there is room above it. The sentence states the arithmetic
        // rather than characterising the interface.
        format!(
            "{requests} requests in {}, longest silence {}; {HEADROOM} times that \
             is still under the {} floor",
            minutes(span.max(watched_for)),
            secs(longest_gap),
            secs(FLOOR)
        )
    } else if longest_gap * HEADROOM > CEILING {
        format!(
            "{requests} requests in {}, longest silence {} — longer than a day \
             with room above it. Capped; this interface may be too quiet to \
             watch this way",
            minutes(span.max(watched_for)),
            secs(longest_gap)
        )
    } else {
        format!(
            "{requests} requests in {}, longest silence {}, times {HEADROOM} \
             for room",
            minutes(span.max(watched_for)),
            secs(longest_gap)
        )
    };
    (Some(suggested), because)
}

/// A duration in whole minutes, or seconds when that reads better.
fn minutes(s: u64) -> String {
    match s {
        0..=90 => format!("{s}s"),
        _ => format!("{}m", (s + 30) / 60),
    }
}

fn secs(s: u64) -> String {
    match s {
        0..=90 => format!("{s}s"),
        _ => format!("{}m{}s", s / 60, s % 60),
    }
}

/// The block to paste into the configuration.
#[must_use]
pub fn as_config(all: &[Suggestion]) -> String {
    let usable: Vec<&Suggestion> = all.iter().filter(|s| s.idle_seconds.is_some()).collect();
    if usable.is_empty() {
        return "  (nothing to suggest: no interface relayed enough to measure)".to_owned();
    }
    let mut out = String::from("  \"per_relay\": {\n");
    for (i, s) in usable.iter().enumerate() {
        let comma = if i + 1 == usable.len() { "" } else { "," };
        let _ = writeln!(
            out,
            "    \"{}\": {{ \"idle_seconds\": {} }}{comma}",
            s.gi,
            s.idle_seconds.unwrap_or(FLOOR)
        );
    }
    out.push_str("  }");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(requests: u64, span: u64, gap: u64) -> (Option<u64>, String) {
        judge(requests, span, gap, 3_600)
    }

    // A busy CMTS: thousands of modems, never silent for long. The floor is
    // what applies, because below five minutes a threshold fires on a line
    // card reloading.
    #[test]
    fn a_busy_interface_gets_the_floor() {
        let (idle, why) = one(240_000, 3_600, 2);
        assert_eq!(idle, Some(300));
        assert!(why.contains("under the 5m0s floor"), "{why}");
    }

    // The sentence has to be true of the interface it is about. A live run
    // printed "busy enough that the floor applies" beside an interface that
    // had been silent for a minute and a half, which is not busy -- it is one
    // whose silence still fits under five minutes with room above it.
    #[test]
    fn the_floor_says_the_arithmetic_not_that_the_interface_is_busy() {
        let (idle, why) = one(12, 180, 93);
        assert_eq!(idle, Some(300), "93 x 3 is under the floor");
        assert!(
            !why.contains("Busy"),
            "an interface silent for 1m33s: {why}"
        );
        assert!(why.contains("1m33s"), "{why}");
        assert!(why.contains("still under"), "{why}");
    }

    // A quiet one: forty modems, twenty minutes between requests. Three times
    // that, because the longest gap in an hour is not the longest gap in a
    // week.
    #[test]
    fn a_quiet_interface_gets_room_above_its_longest_silence() {
        let (idle, why) = one(4, 3_600, 1_200);
        assert_eq!(idle, Some(3_600));
        assert!(why.contains("4 requests"), "{why}");
        assert!(why.contains("20m0s"), "{why}");
    }

    // Nothing arrived. There is no threshold for that: the interface may be
    // idle or it may already be broken, and an hour of silence cannot tell
    // the difference. Suggesting one would write today's outage into the
    // configuration as tomorrow's normal.
    #[test]
    fn an_interface_that_said_nothing_gets_no_suggestion() {
        let (idle, why) = one(0, 0, 0);
        assert_eq!(idle, None);
        assert!(why.contains("cannot tell the difference"), "{why}");
    }

    // One request is a data point, not an interval.
    #[test]
    fn one_request_is_not_enough_to_measure_a_gap() {
        let (idle, why) = one(1, 0, 0);
        assert_eq!(idle, None);
        assert!(why.contains("at least two"), "{why}");
    }

    // An interface silent for most of a day is one this cannot usefully
    // watch, and a threshold of a week reads as monitoring while being none.
    #[test]
    fn a_gap_too_long_to_watch_is_capped_and_says_so() {
        let (idle, why) = one(3, 86_400, 40_000);
        assert_eq!(idle, Some(86_400));
        assert!(why.contains("too quiet to watch"), "{why}");
    }

    #[test]
    fn the_block_can_be_pasted_into_the_configuration() {
        let all = vec![
            Suggestion {
                gi: "10.100.0.1".parse().expect("an address"),
                requests: 100,
                span: 3_600,
                longest_gap: 4,
                idle_seconds: Some(300),
                because: String::new(),
            },
            Suggestion {
                gi: "10.100.0.2".parse().expect("an address"),
                requests: 3,
                span: 3_600,
                longest_gap: 1_200,
                idle_seconds: Some(3_600),
                because: String::new(),
            },
            // Nothing to say about this one; it must not appear.
            Suggestion {
                gi: "10.100.0.3".parse().expect("an address"),
                requests: 0,
                span: 0,
                longest_gap: 0,
                idle_seconds: None,
                because: String::new(),
            },
        ];
        let block = as_config(&all);
        assert!(
            block.contains(r#""10.100.0.1": { "idle_seconds": 300 },"#),
            "{block}"
        );
        assert!(
            block.contains(r#""10.100.0.2": { "idle_seconds": 3600 }"#),
            "{block}"
        );
        assert!(!block.contains("10.100.0.3"), "{block}");
        // And it has to be JSON, or it cannot be pasted anywhere.
        let whole = format!("{{\n{}\n}}", block.trim_end_matches('\n'));
        serde_json::from_str::<serde_json::Value>(&whole)
            .unwrap_or_else(|e| panic!("the block is not valid JSON: {e}\n{whole}"));
    }

    #[test]
    fn nothing_measured_says_so_rather_than_printing_an_empty_block() {
        let block = as_config(&[]);
        assert!(block.contains("nothing to suggest"), "{block}");
    }
}
