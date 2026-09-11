// Copyright MMQR Development
//! Listening to the wire.
//!
//! # Why not libpcap
//!
//! The request was for tcpdump's capture library or the Rust equivalent. On
//! Linux, what libpcap does is open an `AF_PACKET` socket and bind it to an
//! interface, and `pnet_datalink` opens the same socket without a C library
//! in the way. That matters here for two concrete reasons rather than as a
//! preference:
//!
//! * This host has libpcap's runtime but not its headers, so the `pcap` crate
//!   would not build on the machine the code is written on.
//! * Every binary in this repository is statically linked against musl,
//!   because the distribution server refuses a dynamically linked one -- and
//!   these land on hosts whose libc nobody has checked. Linking libpcap into
//!   that needs a musl build of libpcap, which is a second toolchain to
//!   install and keep.
//!
//! What is given up is the kernel-side BPF filter. Filtering happens in this
//! process instead, which costs one function call per frame and no syscalls;
//! a provisioning interface carries thousands of packets a second, not
//! millions, and `packet::read` rejects a frame that is not UDP in about a
//! dozen bounds-checked reads.
//!
//! # Privileges
//!
//! A capture socket belongs to root or to a binary with `CAP_NET_RAW`. That
//! is the failure everybody meets first, so it is named as itself rather than
//! passed through as a permission error out of a library.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use pnet_datalink::{Channel, Config as PnetConfig, NetworkInterface};

use crate::adapt;
use crate::alarm::{self, RelayVerdict, Repeats, State};
use crate::config::Config;
use crate::counters::{Counters, Flow};
use crate::email;
use crate::packet;
use crate::relays::Relays;
use crate::snmp::{self, Trap, Value};

/// How many flows a report lists.
///
/// Busiest first, so the top rows are the ones worth reading; the count of
/// what was left out goes on the end, because on a plant where four thousand
/// modems each fetched one file the tail is four thousand identical rows.
const SHOWN_FLOWS: usize = 12;

/// How long a read waits before coming back empty.
///
/// It has to come back. A plant that has gone completely silent sends no
/// frames at all, and that is exactly when this program has something to say
/// -- a blocking read with no timeout would sit in the kernel through the
/// whole outage and report it when the traffic came back.
const READ_TIMEOUT: Duration = Duration::from_millis(500);

/// Finds the configured interface among the ones this host has.
///
/// The error lists what there is. "No such device eth0" on a host whose
/// interface is called `ens18` is a message that answers nothing.
pub fn find(want: &str) -> Result<NetworkInterface> {
    let all = pnet_datalink::interfaces();
    if let Some(found) = all.iter().find(|i| i.name == want) {
        return Ok(found.clone());
    }
    let names: Vec<&str> = all.iter().map(|i| i.name.as_str()).collect();
    bail!(
        "this host has no interface called {want}. It has: {}",
        names.join(", ")
    )
}

/// Opens the capture.
pub fn open(
    iface: &NetworkInterface,
    _cfg: &Config,
) -> Result<Box<dyn pnet_datalink::DataLinkReceiver>> {
    let opts = PnetConfig {
        read_timeout: Some(READ_TIMEOUT),
        // Promiscuous, because the traffic being watched is not addressed to
        // this host. DHCP from a relay is unicast to the server and TFTP is a
        // conversation between a modem and the server; on a mirror port or a
        // bridge, none of it has this interface's MAC on it.
        promiscuous: true,
        ..PnetConfig::default()
    };

    match pnet_datalink::channel(iface, opts) {
        Ok(Channel::Ethernet(_tx, rx)) => Ok(rx),
        Ok(_) => bail!(
            "{} is not an Ethernet interface, and this reads Ethernet frames",
            iface.name
        ),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => bail!(
            "not allowed to capture on {}. A capture socket belongs to root or to a \
             binary with CAP_NET_RAW: either run this as root, or grant it once with \
             `setcap cap_net_raw,cap_net_admin=eip <path to docsis_monitor>`.",
            iface.name
        ),
        Err(e) => Err(anyhow::Error::new(e))
            .with_context(|| format!("opening a capture on {}", iface.name)),
    }
}

/// The steady state: read frames, count them, and say something every
/// `report_every` seconds.
pub fn run(
    mut rx: Box<dyn pnet_datalink::DataLinkReceiver>,
    cfg: &Config,
    run_for: Option<u64>,
    adaptation: Option<u64>,
) {
    let began = now();
    let mut counts = Counters::new(cfg.window);
    let mut relays = Relays::default();
    let mut repeats = Repeats::new(cfg.thresholds.resend_after);
    let mut next_report = began + cfg.report_every.max(1);
    // An adaptation run has one job and ends when it is done.
    let deadline = adaptation.map_or(run_for, |mins| Some(mins * 60));

    if let Some(mins) = adaptation {
        println!(
            "ADAPTATION: watching {} for {mins} minute(s) to work out what idle \
             means on each CMTS interface. No alarms will be raised.",
            cfg.interface
        );
    } else {
        println!(
            "watching {}: judging on the last {}s, reporting every {}s, {}",
            cfg.interface,
            cfg.window,
            cfg.report_every.max(1),
            match (cfg.snmp.targets.len(), cfg.mail()) {
                (0, None) => "no trap targets and no mail relay: the log only".to_owned(),
                (0, Some(m)) => format!("mail to {}", m.to.join(", ")),
                (n, None) => format!("{n} trap target(s)"),
                (n, Some(m)) => format!("{n} trap target(s) and mail to {}", m.to.join(", ")),
            }
        );
        // Said once, at the start: a threshold written for an address that
        // does not relay will never fire, and the usual cause is one digit
        // typed wrong in an address that looks right. It cannot be checked
        // until traffic has been seen, so this only lists what was asked for.
        let named = cfg.per_relay.named();
        if !named.is_empty() {
            println!("  per-interface thresholds for: {}", named.join(", "));
        }
    }

    loop {
        if let Some(secs) = deadline {
            if now().saturating_sub(began) >= secs {
                break;
            }
        }

        // A timed-out read is the ordinary case on a quiet plant and is not an
        // error. Anything else is reported and the loop carries on: a monitor
        // that exits on one bad frame is a monitor that is not watching.
        match rx.next() {
            Ok(frame) => {
                if let Some(seen) = packet::read(frame) {
                    let (at, at_ms) = (now(), now_ms());
                    counts.add(
                        seen.kind,
                        Flow {
                            src: seen.src,
                            dst: seen.dst,
                            gi: seen.gi,
                        },
                        at,
                    );
                    match seen.kind {
                        packet::Kind::ClientRequest => {
                            relays.request(seen.gi, seen.xid, at, at_ms);
                        }
                        packet::Kind::ServerReply => relays.reply(seen.gi, seen.xid, at, at_ms),
                        packet::Kind::TftpRequest => relays.tftp_request(at),
                        packet::Kind::TftpReply => relays.tftp_send(at),
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => println!("capture read failed: {e}"),
        }

        let at = now();
        if at >= next_report {
            next_report = at + cfg.report_every.max(1);
            if adaptation.is_some() {
                progress(&mut counts, at);
            } else {
                report(&mut counts, &mut relays, cfg, &mut repeats, at, began);
            }
        }
    }

    if let Some(mins) = adaptation {
        write_suggestions(&relays, mins * 60);
        return;
    }
    let total = counts.total();
    println!(
        "stopping: {} requests, {} replies, {} tftp requests seen in all",
        total.requests, total.replies, total.tftp_reads
    );
}

/// One line while an adaptation run is under way, so it is visibly working.
fn progress(counts: &mut Counters, at: u64) {
    let w = counts.window(at);
    println!(
        "  still watching: {} requests, {} replies, {} tftp requests in the last window",
        w.requests, w.replies, w.tftp_reads
    );
}

/// What an adaptation run is for: the numbers, and a block to paste.
fn write_suggestions(relays: &Relays, watched_for: u64) {
    let all = adapt::suggest(relays, watched_for);
    println!();
    println!(
        "─── what this plant looks like after {} ───",
        watched_for / 60
    );
    if all.is_empty() {
        println!("  No CMTS relayed anything at all. Either nothing is being");
        println!("  provisioned, or this is not the interface the relays reach the");
        println!("  server on.");
        return;
    }
    for s in &all {
        match s.idle_seconds {
            Some(n) => println!(
                "  {:<16} idle_seconds {n:<7} {}",
                s.gi.to_string(),
                s.because
            ),
            None => println!("  {:<16} no suggestion — {}", s.gi.to_string(), s.because),
        }
    }
    let u = relays.unrelayed();
    println!(
        "  TFTP saw {} requests and {} sends. It is not alarmed on and has no",
        u.tftp_requests, u.tftp_sends
    );
    println!("  threshold: the equipment behind a modem never touches it, so a plant");
    println!("  fetches a config when a modem boots and not again.");
    println!();
    println!("Paste into the configuration, and read the numbers above first:");
    println!("{}", adapt::as_config(&all));
    println!();
    println!("This watched one window of one day. A plant is busiest in the evening");
    println!("and quietest at four in the morning; neither is in here unless you");
    println!("ran it then.");
}

/// Writes the window to the log, judges it, and sends a trap if it says so.
fn report(
    counts: &mut Counters,
    relays: &mut Relays,
    cfg: &Config,
    repeats: &mut Repeats,
    at: u64,
    began: u64,
) {
    let w = counts.window(at);
    let verdicts = judge_each(relays, cfg, at);
    let state = alarm::worst(&verdicts);
    println!("{}", heading(cfg, w, &state, at));

    per_relay_lines(relays, &verdicts, at);
    flow_lines(counts, at);

    if !should_tell(cfg, repeats, &state, at) {
        return;
    }
    let mail = cfg.mail();

    let busiest = busiest(counts, at);
    if !cfg.snmp.targets.is_empty() {
        let trap = build(cfg, &state, w, at, began, &busiest);
        for target in &cfg.snmp.targets {
            match snmp::send(target, &trap) {
                Ok(()) => println!(
                    "    trap sent to {}:{} — {}",
                    target.host,
                    target.port,
                    state.word()
                ),
                Err(e) => println!("    trap to {}:{} failed: {e}", target.host, target.port),
            }
        }
    }

    if let Some(m) = mail {
        let msg = email::compose(
            &m.subject_prefix,
            &host_name(cfg),
            &cfg.interface,
            state.word(),
            w,
            cfg.window,
            &busiest,
        );
        match email::send(m, &msg) {
            Ok(()) => println!("    mailed {} via {}", m.to.join(", "), m.server),
            // The subject goes in the log when the send fails, so the finding
            // survives even though the message did not.
            Err(e) => println!("    mail via {} failed: {e} — {}", m.server, msg.subject),
        }
    }
}

/// Judges every interface on its own terms.
///
/// One CMTS out of twelve gone quiet is an outage for everybody behind it,
/// and a single threshold over the whole plant averages that away.
fn judge_each(relays: &Relays, cfg: &Config, at: u64) -> Vec<RelayVerdict> {
    relays
        .each()
        .iter()
        .map(|(gi, r)| {
            alarm::judge_relay(
                r.requests,
                r.replies,
                r.idle_for(at),
                cfg.per_relay.idle_seconds(*gi, cfg.thresholds.idle_seconds),
                cfg.thresholds.min_answered,
            )
        })
        .collect()
}

/// The head of one report: a blank line, the moment it was taken, and then the
/// plant's own line.
///
/// Every count under it is relative -- "the last 300 seconds" -- and a log
/// read a week later has nothing to measure that against. The blank line ahead
/// of the stamp turns each report into a paragraph, so a file holding a
/// night's worth is read by eye and cut by date rather than scrolled through.
///
/// Local time rather than UTC, and the zone is named. Somebody reading this is
/// comparing it against a trouble ticket, a CMTS log and their own memory of
/// when the phone started ringing, and all three are in the zone they are
/// standing in.
fn heading(cfg: &Config, w: crate::counters::Window, state: &State, at: u64) -> String {
    format!("\n{}\n{}", local_stamp(at), window_line(cfg, w, state))
}

/// One epoch as `2026-09-08 12:15:54 MDT` in the machine's own zone.
fn local_stamp(at: u64) -> String {
    let Some(ts) = i64::try_from(at)
        .ok()
        .and_then(|s| jiff::Timestamp::from_second(s).ok())
    else {
        // Only reachable when the clock reads outside the range jiff can
        // represent, which means the epoch is nonsense. Say the number rather
        // than inventing a date for it.
        return format!("{at} (not a representable date)");
    };
    ts.to_zoned(jiff::tz::TimeZone::system())
        .strftime("%Y-%m-%d %H:%M:%S %Z")
        .to_string()
}

/// The plant's own line: everything over the window, and the verdict.
fn window_line(cfg: &Config, w: crate::counters::Window, state: &State) -> String {
    format!(
        "{}s window: {} requests, {} replies ({:.0}% answered), {} tftp requests, {} tftp sends — {}",
        cfg.window,
        w.requests,
        w.replies,
        w.answered() * 100.0,
        w.tftp_reads,
        w.tftp_sends,
        state.word()
    )
}

/// One line per CMTS interface: what it did, whether it was answered, and how
/// fast.
///
/// Counting replies is not knowing requests were answered. Two thousand of
/// each can be everything answered in four milliseconds, or half of them
/// answered twice, four seconds late -- and the second is a server about to
/// stop being one.
fn per_relay_lines(relays: &Relays, verdicts: &[RelayVerdict], at: u64) {
    for ((gi, r), v) in relays.each().iter().zip(verdicts) {
        let answers = match r.answer_ms_mean() {
            Some(mean) => format!("{mean}ms mean, {}ms worst", r.answer_ms_worst),
            None => "nothing answered".to_owned(),
        };
        println!(
            "    {:<16} {:>7} req {:>7} rep  {:>6} answered, {answers}  idle {} of {}s — {}",
            gi.to_string(),
            r.requests,
            r.replies,
            r.answered,
            r.idle_for(at)
                .map_or_else(|| "never".to_owned(), |s| format!("{s}s")),
            v.idle_allowed,
            v.state.word(),
        );
    }
    // Requests with no answer yet. On a healthy plant this is a handful --
    // the ones in flight at the moment the line was written. A number that
    // climbs across reports is a server that has stopped answering, seen
    // before the ratio has moved enough to say so.
    if relays.waiting() > 0 {
        println!(
            "    {} request(s) still waiting for an answer",
            relays.waiting()
        );
    }
    // TFTP has no gi-address to file it under, and is far quieter than DHCP
    // in any case: the equipment behind a modem never touches it, so a plant
    // fetches a config when a modem boots and not again.
    let u = relays.unrelayed();
    if u.total() > 0 {
        println!(
            "    {:<16} {:>7} req {:>7} rep  {} tftp requests, {} tftp sends",
            "(no gi-address)", u.requests, u.replies, u.tftp_requests, u.tftp_sends
        );
    }
}

/// Both ends of the busiest conversations.
///
/// The per-interface lines above say what each CMTS did; this says who was
/// actually talking. They answer different questions and neither replaces the
/// other: a gi-address names the interface, and the pair of addresses names
/// the two machines to look at when the interface is fine and something
/// between them is not.
fn flow_lines(counts: &mut Counters, at: u64) {
    let flows = counts.by_flow(at);
    for (f, d) in flows.iter().copied().take(SHOWN_FLOWS) {
        let gi = f.gi.map_or_else(String::new, |g| format!(" gi {g}"));
        println!(
            "    {:>15} -> {:<15}{:<18} {:>6} req {:>6} rep {:>6} tftp-req {:>6} tftp-send",
            f.src.to_string(),
            f.dst.to_string(),
            gi,
            d.counts[0],
            d.counts[1],
            d.counts[2],
            d.counts[3],
        );
    }
    // Busiest first means the top rows are the ones worth reading, but on a
    // plant where four thousand modems each fetched one file the tail is four
    // thousand identical rows -- and showing ten with nothing to say so reads
    // as though that were all there was.
    if flows.len() > SHOWN_FLOWS {
        println!("    ... and {} more", flows.len() - SHOWN_FLOWS);
    }
}

/// Whether anybody is told about this state, and now.
///
/// Two questions in one place. Is there anywhere to send it -- a trap target
/// or a mail relay -- and is it due? With neither configured, nothing is said
/// AT ALL, including in the log: the state is already on the report line above,
/// and a monitor that logs its own inaction every window is a monitor whose log
/// nobody reads.
///
/// The repeat gate is only consulted when there is somewhere to send, so a run
/// with nothing configured does not quietly use up the "already said that"
/// memory and then stay silent for fifteen minutes after a relay is added.
fn should_tell(cfg: &Config, repeats: &mut Repeats, state: &State, at: u64) -> bool {
    if cfg.snmp.targets.is_empty() && cfg.mail().is_none() {
        return false;
    }
    repeats.should_send(state, at)
}

/// The destination carrying the most traffic in the window, for the alert.
///
/// It is what turns "requests have stopped" into somewhere to go and look: on
/// a plant with four relays, three still talking and one silent names the one
/// to check.
fn busiest(counts: &mut Counters, at: u64) -> String {
    counts.by_flow(at).first().map_or_else(
        || "none".to_owned(),
        |(f, _)| match f.gi {
            // The gi-address when there is one: that is the interface an
            // operator goes and looks at, and the source of a relayed request
            // is the relay, which fronts many of them.
            Some(g) => format!("{} via {}", f.src, g),
            None => format!("{} -> {}", f.src, f.dst),
        },
    )
}

/// Builds the trap for a state.
fn build(
    cfg: &Config,
    state: &State,
    w: crate::counters::Window,
    at: u64,
    began: u64,
    busiest: &str,
) -> Trap {
    Trap {
        // TimeTicks are hundredths of a second.
        uptime_ticks: at.saturating_sub(began) * 100,
        which: match state {
            State::Working => 3,
            State::Quiet => 1,
            State::Unanswered => 2,
        },
        bindings: vec![
            (Trap::field(1), Value::Str(host_name(cfg))),
            (Trap::field(2), Value::Str(cfg.interface.clone())),
            (Trap::field(3), Value::Str(state.word().to_owned())),
            (Trap::field(4), Value::Count(w.requests)),
            (Trap::field(5), Value::Count(w.replies)),
            (Trap::field(6), Value::Count(w.tftp_reads)),
            (Trap::field(7), Value::Count(cfg.window)),
            (Trap::field(8), Value::Str(busiest.to_owned())),
        ],
    }
}

/// What the traps call this host.
fn host_name(cfg: &Config) -> String {
    if let Some(n) = &cfg.snmp.sysname {
        return n.clone();
    }
    nix::unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The same, in milliseconds.
///
/// Answer times are measured in single figures of milliseconds on a healthy
/// plant, so seconds would report every one of them as zero -- and "answered
/// in 0 seconds" and "answered in 900ms" are the difference between a server
/// that is fine and one that is about to stop being fine.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The interface being missing is the second thing that goes wrong, after
    // privileges. "No such device eth0" on a host whose interface is ens18
    // answers nothing, so the error lists what there is.
    #[test]
    fn a_missing_interface_names_the_ones_there_are() {
        let e = find("definitely-not-an-interface").expect_err("no such interface");
        let text = format!("{e:#}");
        assert!(text.contains("definitely-not-an-interface"), "{text}");
        assert!(text.contains("It has:"), "{text}");
        // Every host has a loopback, so the list is never empty.
        assert!(text.contains("lo"), "{text}");
    }

    fn config(json: &str) -> Config {
        serde_json::from_str(json).expect("a configuration")
    }

    // Nothing configured to tell means nothing is said, including in the log.
    // The state is already on the report line, and a monitor that logs its own
    // inaction every window is a monitor whose log nobody reads.
    #[test]
    fn with_nowhere_to_send_nothing_is_said() {
        let cfg = config(r#"{"interface":"eth0"}"#);
        let mut r = Repeats::new(900);
        assert!(!should_tell(&cfg, &mut r, &State::Quiet, 0));
        assert!(!should_tell(&cfg, &mut r, &State::Unanswered, 1_000));
        assert!(!should_tell(&cfg, &mut r, &State::Working, 2_000));
    }

    // And the repeat memory is not quietly used up while nothing is
    // configured, or adding a relay would be followed by fifteen minutes of
    // silence about an outage already under way.
    #[test]
    fn a_relay_added_later_hears_about_the_outage_at_once() {
        let quiet = config(r#"{"interface":"eth0"}"#);
        let mut r = Repeats::new(900);
        for t in 0..5 {
            assert!(!should_tell(&quiet, &mut r, &State::Quiet, t * 300));
        }
        let now_configured =
            config(r#"{"interface":"eth0","smtp":{"server":"mail","from":"a@b","to":["c@d"]}}"#);
        assert!(
            should_tell(&now_configured, &mut r, &State::Quiet, 1_500),
            "the outage is still on and nobody has been told yet"
        );
    }

    #[test]
    fn a_mail_relay_alone_is_somewhere_to_send() {
        let cfg =
            config(r#"{"interface":"eth0","smtp":{"server":"mail","from":"a@b","to":["c@d"]}}"#);
        let mut r = Repeats::new(900);
        assert!(should_tell(&cfg, &mut r, &State::Quiet, 0));
        assert!(
            !should_tell(&cfg, &mut r, &State::Quiet, 300),
            "not again yet"
        );
    }

    // What was asked for, in the order it was asked for: a blank line, the
    // local time, and then the window on the line after it. Asserted on the
    // text rather than on the terminal, because the ordering is the whole
    // requirement and printing it is not something a unit test can watch.
    #[test]
    fn a_report_opens_with_a_blank_line_then_the_stamp_then_the_window() {
        let cfg = config(r#"{"interface":"eth0","window":300}"#);
        let at: u64 = 1_757_355_354;
        let mut counts = Counters::new(cfg.window);
        let head = heading(&cfg, counts.window(at), &State::Working, at);
        let lines: Vec<&str> = head.split('\n').collect();
        assert_eq!(
            lines.len(),
            3,
            "three lines, the first of them empty: {head:?}"
        );
        assert_eq!(lines[0], "", "a report opens with a blank line");
        assert_eq!(lines[1], local_stamp(at), "then the local time, alone");
        assert!(
            lines[2].starts_with("300s window:"),
            "then the window: {:?}",
            lines[2]
        );
    }

    // The stamp dates every count under it, so the fields have to be the
    // right ones, in the order they are read in, and padded so a column of
    // them lines up. Checked against jiff's own accessors rather than against
    // a literal: this machine's zone is whatever it is, and a test that only
    // passes in one zone is a test that fails on the plant.
    #[test]
    fn the_stamp_carries_the_local_date_and_time_in_order() {
        let at: u64 = 1_757_355_354;
        let z = jiff::Timestamp::from_second(i64::try_from(at).expect("in range"))
            .expect("a date")
            .to_zoned(jiff::tz::TimeZone::system());
        let want = format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} ",
            z.year(),
            z.month(),
            z.day(),
            z.hour(),
            z.minute(),
            z.second()
        );
        let got = local_stamp(at);
        assert!(got.starts_with(&want), "{got:?} does not start {want:?}");
        assert!(
            got.len() > want.len(),
            "the zone is named as well, or a log moved between machines is ambiguous: {got:?}"
        );
    }

    // Two reports a minute apart must not carry the same stamp, which is the
    // one way this could look right and say nothing.
    #[test]
    fn a_later_report_carries_a_later_stamp() {
        let a = local_stamp(1_757_355_354);
        let b = local_stamp(1_757_355_354 + 60);
        assert_ne!(a, b);
    }

    // `now()` reports 0 when the clock cannot be read at all, and a clock can
    // read as something jiff has no date for. Neither is worth inventing a
    // date over: the number is the finding.
    #[test]
    fn an_unrepresentable_clock_says_the_number_instead_of_a_date() {
        let got = local_stamp(u64::MAX);
        assert!(got.contains(&u64::MAX.to_string()), "{got:?}");
        assert!(!got.contains('-'), "no date was invented: {got:?}");
    }

    #[test]
    fn a_trap_target_alone_is_somewhere_to_send() {
        let cfg = config(r#"{"interface":"eth0","snmp":{"targets":[{"host":"10.0.0.9"}]}}"#);
        let mut r = Repeats::new(900);
        assert!(should_tell(&cfg, &mut r, &State::Quiet, 0));
    }

    // A half-filled mail section is not somewhere to send. `Config::check`
    // refuses it on the way in; this is the second line, for a section that
    // reached here some other way.
    #[test]
    fn a_mail_section_with_no_recipients_is_nowhere_to_send() {
        let cfg = config(r#"{"interface":"eth0","smtp":{"server":"mail","from":"a@b","to":[]}}"#);
        let mut r = Repeats::new(900);
        assert!(!should_tell(&cfg, &mut r, &State::Quiet, 0));
    }

    #[test]
    fn the_loopback_is_found_by_name() {
        let lo = find("lo").expect("every host has a loopback");
        assert_eq!(lo.name, "lo");
    }
}
