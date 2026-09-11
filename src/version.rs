// Copyright MMQR Development
//! When a binary was built, and how it says so.
//!
//! Every program in this repository answers `--version` with one line:
//!
//! ```text
//! 1788637958 2026-9-5 13:52:38
//! ```
//!
//! The epoch seconds come first because that is the part that is exact and
//! comparable — "is the server older than the tool?" is a subtraction. The
//! local date and time after it is for the person reading, and is why the
//! month, day and hour are not zero-padded while the minute and second are:
//! the first half reads as a date, the second as a time.
//!
//! # Where the stamp comes from
//!
//! Normally the executable's own modification time, which is exactly when the
//! linker wrote it. That makes `--version` work for a plain `cargo build` with
//! no special incantation to remember, and it is the reason this is not a
//! `build.rs` — a build script stamps the *compile*, and then a cached
//! artefact from last week reports today.
//!
//! A release build can pin it instead, which is worth doing whenever the
//! binary might be copied around: `cp` without `-p` rewrites mtime, and an
//! unpacked archive can carry any timestamp at all.
//!
//! ```sh
//! DOCSIS_BUILD_TIME=$(date +%s) cargo build --release
//! ```
//!
//! When neither is available the stamp is epoch 0, which formats as a
//! obviously wrong 1970 date rather than silently claiming "now" — a plausible
//! lie is worse than a visible gap.
//!
//! # Why this file is copied
//!
//! `docsis_tester`, `fake_docsis_server` and `docsis_config_generator` are each
//! their own workspace, deliberately sharing no code with the server they test
//! or serve. Sixty lines of date formatting is a cheaper price than a shared
//! crate that would undo that. The copies must stay identical: every binary in
//! this repository answers `--version` the same way, and a fleet where two of
//! them disagree about the format is worse than one where none of them
//! answers.

use std::time::UNIX_EPOCH;

/// The pinned build time, if the build set one.
const PINNED: Option<&str> = option_env!("DOCSIS_BUILD_TIME");

/// Seconds since the epoch at which this executable was built.
#[must_use]
pub fn build_epoch() -> i64 {
    if let Some(t) = PINNED.and_then(|s| s.trim().parse::<i64>().ok()) {
        return t;
    }
    std::env::current_exe()
        .and_then(std::fs::metadata)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

/// The one line `--version` prints.
#[must_use]
pub fn build_stamp() -> String {
    format(build_epoch())
}

/// Renders one epoch as `<epoch> <year>-<month>-<day> <hour>:<minute>:<second>`
/// in the machine's own time zone.
#[must_use]
pub fn format(epoch: i64) -> String {
    let Ok(ts) = jiff::Timestamp::from_second(epoch) else {
        // Only reachable for an epoch outside the range jiff represents, which
        // means the mtime was nonsense. Say the number and nothing more rather
        // than inventing a date for it.
        return format!("{epoch} (not a representable date)");
    };
    let z = ts.to_zoned(jiff::tz::TimeZone::system());
    format!(
        "{epoch} {}-{}-{} {}:{:02}:{:02}",
        z.year(),
        z.month(),
        z.day(),
        z.hour(),
        z.minute(),
        z.second()
    )
}

/// Prints the build stamp and exits when `--version` or `-V` was asked for.
///
/// Called as the first statement of `main`, before the argument parser. Asking
/// a binary when it was built must not depend on the rest of the command line
/// being valid, on a readable configuration file, or on a reachable database —
/// those are exactly the situations in which somebody wants to know which
/// build they are looking at.
pub fn print_and_exit_if_requested() {
    if std::env::args_os().any(|a| a == "--version" || a == "-V") {
        println!("{}", build_stamp());
        std::process::exit(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_comes_first_and_the_date_matches_it() {
        // 2026-09-05 19:52:38 UTC. The local rendering depends on the machine,
        // so what is pinned here is the shape and the epoch, not the hour.
        let s = format(1_788_637_958);
        let (epoch, rest) = s.split_once(' ').expect("epoch then date");
        assert_eq!(epoch, "1788637958");
        let (date, time) = rest.split_once(' ').expect("date then time");
        assert_eq!(date.split('-').count(), 3, "date was {date}");
        assert_eq!(time.split(':').count(), 3, "time was {time}");
        assert!(date.starts_with("2026-9-"), "date was {date}");
    }

    #[test]
    fn the_minute_and_second_are_padded_but_the_date_and_hour_are_not() {
        // A time has to read as a time -- 9:5:3 is not one -- while a date
        // padded to 2026-09-05 reads as machine output.
        //
        // Asserted over a year of samples rather than one chosen moment: which
        // calendar day an epoch falls on depends on the machine's zone, and an
        // earlier version of this test passed only west of Greenwich.
        let mut saw_short_month = false;
        let mut saw_short_hour = false;
        for i in 0..400i64 {
            let s = format(1_767_236_523 + i * 86_400 + i * 3_607);
            let rest = s.split_once(' ').expect("epoch then the rest").1;
            let (date, time) = rest.split_once(' ').expect("date then time");
            let d: Vec<&str> = date.split('-').collect();
            let t: Vec<&str> = time.split(':').collect();
            assert_eq!(t[1].len(), 2, "the minute must be padded: {s}");
            assert_eq!(t[2].len(), 2, "the second must be padded: {s}");
            for part in [d[1], d[2], t[0]] {
                assert!(
                    part.len() == 1 || !part.starts_with('0'),
                    "the date and hour must not be padded: {s}"
                );
            }
            saw_short_month |= d[1].len() == 1;
            saw_short_hour |= t[0].len() == 1;
        }
        assert!(
            saw_short_month && saw_short_hour,
            "the samples never reached a single-digit month or hour"
        );
    }

    #[test]
    fn an_unbuildable_stamp_is_visibly_wrong_rather_than_plausible() {
        // Zero is what an unreadable executable yields. It must not look like
        // a real build, because a plausible lie is worse than a visible gap.
        assert!(format(0).starts_with("0 19"), "{}", format(0));
    }

    #[test]
    fn a_real_binary_reports_a_time_that_is_not_the_epoch() {
        // The test binary is an executable this build wrote, so the mtime path
        // has to produce something recent. A test that only exercised `format`
        // would pass with `build_epoch` returning 0 for ever.
        assert!(
            build_epoch() > 1_700_000_000,
            "build_epoch() gave {}, so the executable's own mtime was not read",
            build_epoch()
        );
    }
}
