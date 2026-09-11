// Copyright MMQR Development
//! What to watch, what counts as trouble, and who to tell.
//!
//! One JSON file, `~/config/docsis_monitor.json`, with every setting in it.
//! Nothing here is a command-line flag: a monitor is started once and then
//! left running for months, usually by a supervisor, and a setting that lives
//! on a command line is a setting nobody can find six months later.
//!
//! ```json
//! {
//!   "interface": "eth0",
//!   "window": 300,
//!   "report_every": 300,
//!   "thresholds": { "min_requests": 5, "min_answered": 0.75 },
//!   "snmp": {
//!     "targets": [{ "host": "10.0.0.9", "community": "public" }],
//!     "sysname": "docsis-prov-1"
//!   }
//! }
//! ```
//!
//! # Unknown keys are named, not refused
//!
//! A misspelt `"min_requsts"` is a threshold that never fires, on a program
//! whose entire job is to fire it. There is nothing on any screen to notice
//! that by -- a monitor that never alarms looks exactly like a plant that is
//! working. So anything not recognised is printed at startup. It is not an
//! error, because a key added to this file by a later version should not stop
//! the running one; keys beginning `//` are comments and pass in silence.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// The file's name, in both places it is looked for.
const FILE: &str = "docsis_monitor.json";

/// Everything this program does.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// The interface to watch, by name. `"any"` is not accepted: a monitor
    /// that cannot say which wire it is watching cannot say which wire went
    /// quiet.
    pub interface: String,

    /// Stay in the foreground. `--nofork` says the same thing for one run.
    #[serde(default)]
    pub nofork: bool,

    /// How many seconds of history a decision is made over.
    ///
    /// Long enough that one slow minute is not an alarm, short enough that a
    /// real outage is caught before the phone rings. Five minutes is both.
    #[serde(default = "default_window")]
    pub window: u64,

    /// How often the counts are written to the log, in seconds.
    ///
    /// Separate from `window` because they answer different questions: the
    /// window is how much history a judgement uses, this is how often a line
    /// appears for somebody reading afterwards.
    #[serde(default = "default_report")]
    pub report_every: u64,

    /// What counts as trouble.
    #[serde(default)]
    pub thresholds: Thresholds,

    /// Where to send a trap. No targets means no traps.
    #[serde(default)]
    pub snmp: Snmp,

    /// What each named interface expects, instead of `idle_seconds`.
    #[serde(default)]
    pub per_relay: PerRelay,

    /// Where to send mail. No server or no recipients means no mail.
    ///
    /// A trap goes to a network management platform, which not every plant
    /// has. A mail relay, every plant has.
    #[serde(default)]
    pub smtp: Option<Smtp>,

    /// Anything else in the file. See the module header: named at startup,
    /// never refused.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

const fn default_window() -> u64 {
    300
}
const fn default_report() -> u64 {
    300
}

/// What one CMTS interface's normal looks like.
///
/// A plant is not one thing. One interface carries several thousand modems
/// and should never be silent for five minutes; another carries forty and is
/// properly silent for an hour at a time. One number over the whole plant is
/// wrong for both: set for the busy one it cries wolf about the quiet one
/// every night, and set for the quiet one it says nothing for an hour after
/// the busy one falls over.
///
/// `--adaptation` watches a plant and prints one of these for every interface
/// it saw, so the numbers are measured rather than guessed at.
#[derive(Clone, Copy, Debug, Deserialize)]
pub struct RelayThreshold {
    /// The longest silence that is still normal here, in seconds.
    ///
    /// Not a count in a window, because the windows differ: "at least one
    /// request every five minutes" and "at least one every hour" are the same
    /// sentence with a different number, and a count would need a different
    /// window for each interface to say it.
    pub idle_seconds: u64,
}

/// The two ways provisioning fails from a distance.
///
/// Every field has a default. A `thresholds` block that names one setting must
/// not fail to parse because it did not name the other three -- and more to
/// the point, a version of this program that adds a fourth must not refuse to
/// start against every configuration file written for the third. A monitor
/// that will not start is a monitor that is not watching, and the way anybody
/// finds out is the outage it was there for.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    /// Least fraction of client requests that must be answered, 0 to 1.
    ///
    /// The "arriving and going unanswered" alarm: a server that is up,
    /// listening, and refusing or failing everything reads as silence in
    /// exactly the same way as one that is down.
    ///
    /// Not evaluated until `min_requests` have arrived. A ratio over three
    /// packets is noise, and a plant with nothing on it would otherwise trip
    /// this every window on the way to tripping the one above.
    pub min_answered: f64,

    /// The longest silence that is normal on an interface nothing else names.
    ///
    /// Every interface not in `per_relay` is judged by this. It is
    /// deliberately generous: an interface nobody has measured should not be
    /// the one that wakes somebody up.
    pub idle_seconds: u64,

    /// How long a trap is not repeated for, in seconds.
    ///
    /// An outage lasting an afternoon is one problem, not fifty. Zero repeats
    /// every window, which is what somebody testing a trap receiver wants and
    /// nobody else does.
    pub resend_after: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            min_answered: 0.75,
            idle_seconds: 3_600,
            resend_after: 900,
        }
    }
}

/// The thresholds, plus what each named interface expects instead.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct PerRelay(pub BTreeMap<String, RelayThreshold>);

impl PerRelay {
    /// How long this interface may be silent for.
    #[must_use]
    pub fn idle_seconds(&self, gi: std::net::Ipv4Addr, fallback: u64) -> u64 {
        self.0
            .get(&gi.to_string())
            .map_or(fallback, |t| t.idle_seconds)
    }

    /// Interfaces named here that this program has never seen a packet from.
    ///
    /// Worth saying at startup: a threshold written for an address that does
    /// not relay is a threshold that will never fire, and the usual cause is
    /// a digit typed wrong in an address that looks right.
    #[must_use]
    pub fn named(&self) -> Vec<&str> {
        self.0.keys().map(String::as_str).collect()
    }
}

/// Where a trap goes.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Snmp {
    /// The receivers. Empty means the log only, which is a legitimate way to
    /// run this: the counts are still written and still worth reading.
    #[serde(default)]
    pub targets: Vec<Target>,

    /// What the traps call this host. Defaults to the system's own name.
    #[serde(default)]
    pub sysname: Option<String>,
}

/// One trap receiver.
#[derive(Clone, Debug, Deserialize)]
pub struct Target {
    pub host: String,
    #[serde(default = "default_trap_port")]
    pub port: u16,
    /// The v2c community. It is a password sent in clear text, which is what
    /// `SNMPv2c` is; it is here because the receiver demands one, not because
    /// it protects anything.
    #[serde(default = "default_community")]
    pub community: String,
}

const fn default_trap_port() -> u16 {
    162
}

fn default_community() -> String {
    "public".to_owned()
}

/// A mail relay to alert through.
///
/// Plain `SMTP`, no `STARTTLS`. See `email` for what that means and when it is
/// the right shape.
#[derive(Clone, Debug, Deserialize)]
pub struct Smtp {
    pub server: String,
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    /// The envelope sender. Relays reject mail from an address they do not
    /// recognise, so this is not decoration.
    pub from: String,
    /// Everyone who gets told. Empty means no mail, which is how the whole
    /// feature is switched off without deleting the section.
    #[serde(default)]
    pub to: Vec<String>,
    /// What every subject starts with, so a mail rule can file these.
    #[serde(default = "default_prefix")]
    pub subject_prefix: String,
    /// `AUTH PLAIN`, when a relay insists on it.
    ///
    /// The password crosses the wire IN CLEAR TEXT: there is no `STARTTLS`
    /// here. If the relay is not on a network you trust, leave these out and
    /// let it accept the mail unauthenticated.
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// What to say in `EHLO`. Defaults to this host's own name.
    #[serde(default)]
    pub helo_name: Option<String>,
}

const fn default_smtp_port() -> u16 {
    25
}

fn default_prefix() -> String {
    "[docsis]".to_owned()
}

impl Smtp {
    /// Whether this section can actually send anything.
    ///
    /// A server with no recipients is a section somebody half filled in, and
    /// it must not read as "mail is configured" anywhere.
    #[must_use]
    pub fn usable(&self) -> bool {
        !self.server.trim().is_empty() && !self.to.is_empty() && !self.from.trim().is_empty()
    }

    /// What to put in `EHLO`.
    #[must_use]
    pub fn helo(&self) -> String {
        self.helo_name.clone().unwrap_or_else(|| {
            nix::unistd::gethostname()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "localhost".to_owned())
        })
    }
}

impl Config {
    /// The mail relay, if one is configured and complete enough to use.
    #[must_use]
    pub fn mail(&self) -> Option<&Smtp> {
        self.smtp.as_ref().filter(|s| s.usable())
    }

    /// Says out loud anything in the file this program does not read.
    pub fn report_unknown(&self) {
        let unknown: Vec<&str> = self
            .extra
            .keys()
            .map(String::as_str)
            .filter(|k| !k.trim_start().starts_with("//"))
            .collect();
        if unknown.is_empty() {
            return;
        }
        println!(
            "ignoring {} setting(s) this program does not know: {}",
            unknown.len(),
            unknown.join(", ")
        );
    }

    /// Refuses a configuration that cannot do anything useful.
    fn check(&self) -> Result<()> {
        if self.interface.trim().is_empty() {
            bail!("`interface` must name the interface to watch");
        }
        if self.interface.trim() == "any" {
            bail!(
                "`interface` must name one interface. \"any\" captures every wire at \
                 once, and a monitor that cannot say WHICH wire went quiet cannot say \
                 anything worth acting on."
            );
        }
        if self.window == 0 {
            bail!("`window` is how many seconds a judgement is made over; it cannot be 0");
        }
        // A half-filled mail section is refused rather than ignored. Somebody
        // who wrote a server and forgot the recipients believes mail is
        // configured, and the way they find out otherwise is an outage nobody
        // was told about.
        if let Some(m) = &self.smtp {
            let named = !m.server.trim().is_empty();
            if named && m.to.is_empty() {
                bail!("`smtp.server` is set but `smtp.to` names nobody to send to");
            }
            if named && m.from.trim().is_empty() {
                bail!(
                    "`smtp.server` is set but `smtp.from` is empty; a relay rejects mail with no sender"
                );
            }
        }
        if !(0.0..=1.0).contains(&self.thresholds.min_answered) {
            bail!(
                "`min_answered` is a fraction of requests, 0 to 1, not a percentage: \
                 {} was given",
                self.thresholds.min_answered
            );
        }
        Ok(())
    }
}

/// Where the file is looked for, in order.
#[must_use]
pub fn search_paths() -> Vec<PathBuf> {
    std::env::home_dir()
        .map(|h| h.join("config"))
        .into_iter()
        .chain(std::iter::once(PathBuf::from("/etc")))
        .map(|d| d.join(FILE))
        .collect()
}

/// Reads the configuration, and says WHICH file it read.
///
/// The path is returned rather than kept quiet because there are two it could
/// be. When a monitor is watching the wrong interface the first question is
/// which file it was told to watch, and answering it in the log costs one
/// line.
pub fn load(explicit: Option<&Path>) -> Result<(Config, PathBuf)> {
    let path = if let Some(p) = explicit {
        p.to_owned()
    } else {
        let tried = search_paths();
        let Some(found) = tried.iter().find(|p| p.exists()) else {
            let list: Vec<String> = tried.iter().map(|p| p.display().to_string()).collect();
            bail!(
                "no {FILE} found. Tried, in order: {}. Every setting this program \
                 has lives in that file.",
                list.join(", ")
            );
        };
        found.clone()
    };
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let cfg: Config =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    cfg.check()
        .with_context(|| format!("in {}", path.display()))?;
    Ok((cfg, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Result<Config> {
        let cfg: Config = serde_json::from_str(json)?;
        cfg.check()?;
        Ok(cfg)
    }

    #[test]
    fn the_smallest_useful_file_is_one_interface() {
        let cfg = parse(r#"{"interface": "eth0"}"#).expect("that is enough");
        assert_eq!(cfg.interface, "eth0");
        assert_eq!(cfg.window, 300);
        assert!(cfg.snmp.targets.is_empty(), "no traps unless asked");
    }

    // A monitor that cannot say WHICH wire went quiet cannot say anything
    // worth acting on, and "any" is the easy thing to type.
    #[test]
    fn capturing_every_interface_at_once_is_refused() {
        let e = parse(r#"{"interface": "any"}"#).expect_err("must be refused");
        assert!(e.to_string().contains("one interface"), "{e}");
    }

    #[test]
    fn an_interface_is_required() {
        assert!(parse(r#"{"interface": "  "}"#).is_err());
        assert!(serde_json::from_str::<Config>("{}").is_err());
    }

    // The ratio is a fraction. Somebody will write 75 meaning 75%, and that
    // would silently mean "every request must be answered more than
    // seventy-five times" -- an alarm that fires for ever.
    #[test]
    fn a_percentage_where_a_fraction_belongs_is_refused() {
        let e = parse(r#"{"interface":"eth0","thresholds":{"min_answered":75,"idle_seconds":300,"resend_after":900}}"#)
            .expect_err("75 is not a fraction");
        assert!(e.to_string().contains("fraction"), "{e}");
    }

    // A version that adds a threshold must not refuse to start against every
    // configuration written for the version before it. A monitor that will
    // not start is a monitor that is not watching, and the way anybody finds
    // out is the outage it was there for.
    #[test]
    fn a_thresholds_block_may_name_one_setting_and_leave_the_rest() {
        let cfg = parse(r#"{"interface":"eth0","thresholds":{"idle_seconds":600}}"#)
            .expect("one setting is enough");
        assert_eq!(cfg.thresholds.idle_seconds, 600);
        assert!(
            (cfg.thresholds.min_answered - 0.75).abs() < 1e-9,
            "the rest keep their defaults"
        );
        assert_eq!(cfg.thresholds.resend_after, 900);
    }

    #[test]
    fn a_window_of_zero_seconds_is_refused() {
        assert!(parse(r#"{"interface":"eth0","window":0}"#).is_err());
    }

    #[test]
    fn a_trap_target_defaults_to_the_snmp_trap_port() {
        let cfg = parse(r#"{"interface":"eth0","snmp":{"targets":[{"host":"10.0.0.9"}]}}"#)
            .expect("parses");
        assert_eq!(cfg.snmp.targets[0].port, 162);
        assert_eq!(cfg.snmp.targets[0].community, "public");
    }

    // A section somebody half filled in must not read as "mail is
    // configured": they believe they will be told, and the way they find out
    // otherwise is an outage nobody heard about.
    #[test]
    fn a_half_filled_mail_section_is_refused() {
        let e = parse(r#"{"interface":"eth0","smtp":{"server":"mail","from":"a@b","to":[]}}"#)
            .expect_err("nobody to send to");
        assert!(e.to_string().contains("names nobody"), "{e}");
        let e = parse(r#"{"interface":"eth0","smtp":{"server":"mail","from":"","to":["a@b"]}}"#)
            .expect_err("no sender");
        assert!(e.to_string().contains("no sender"), "{e}");
    }

    #[test]
    fn a_complete_mail_section_is_usable_and_a_missing_one_is_nothing() {
        let cfg =
            parse(r#"{"interface":"eth0","smtp":{"server":"mail","from":"a@b","to":["c@d"]}}"#)
                .expect("parses");
        let m = cfg.mail().expect("usable");
        assert_eq!(m.port, 25);
        assert_eq!(m.subject_prefix, "[docsis]");
        assert!(m.username.is_none(), "no password unless asked for");

        assert!(
            parse(r#"{"interface":"eth0"}"#)
                .expect("parses")
                .mail()
                .is_none(),
            "no section means no mail"
        );
    }

    #[test]
    fn a_misspelt_setting_is_named_and_a_comment_is_not() {
        let cfg = parse(r#"{"interface":"eth0","windwo":30,"// why":"a note"}"#).expect("parses");
        let unknown: Vec<&str> = cfg
            .extra
            .keys()
            .map(String::as_str)
            .filter(|k| !k.starts_with("//"))
            .collect();
        assert_eq!(unknown, vec!["windwo"]);
    }

    // The example is where an operator copies this from, so every setting in
    // it has to be one this program reads. A key spelled differently there is
    // a setting that silently does nothing on every install that started from
    // it -- and on this program, a setting that does nothing is an alarm that
    // never fires, which looks exactly like a plant that is working.
    #[test]
    fn the_shipped_example_parses_and_sets_nothing_unknown() {
        let text = std::fs::read_to_string("docsis_monitor.example.json")
            .expect("the example ships beside the source");
        let cfg: Config = serde_json::from_str(&text).expect("it parses");
        cfg.check().expect("and it is a usable configuration");

        assert_eq!(cfg.interface, "eth0");
        assert_eq!(cfg.window, 300);
        assert_eq!(cfg.snmp.targets.len(), 1);
        assert_eq!(cfg.snmp.targets[0].port, 162);
        assert_eq!(cfg.thresholds.idle_seconds, 3_600);
        assert_eq!(
            cfg.per_relay
                .idle_seconds("10.100.0.1".parse().expect("an address"), 3_600),
            300,
            "a busy interface's own number"
        );
        assert_eq!(
            cfg.per_relay
                .idle_seconds("10.9.9.9".parse().expect("an address"), 3_600),
            3_600,
            "and anything not named falls back"
        );
        let mail = cfg.mail().expect("the example configures a relay");
        assert_eq!(mail.port, 25);
        assert_eq!(mail.to, vec!["noc@example.com".to_owned()]);
        assert!(
            mail.password.is_none(),
            "the example must not ship a password: it would cross the wire in clear"
        );

        let unknown: Vec<&str> = cfg
            .extra
            .keys()
            .map(String::as_str)
            .filter(|k| !k.trim_start().starts_with("//"))
            .collect();
        assert!(
            unknown.is_empty(),
            "the example sets {unknown:?}, which this program does not read"
        );
    }

    #[test]
    fn the_users_own_directory_is_searched_first() {
        let paths = search_paths();
        assert!(paths.len() >= 2, "{paths:?}");
        assert!(paths.last().expect("a last path").starts_with("/etc"));
        assert!(paths.iter().all(|p| p.ends_with(FILE)), "{paths:?}");
    }
}
