// Copyright MMQR Development
//! Deciding whether what was counted is trouble.
//!
//! Two questions, which fail the same way from a distance and have completely
//! different causes:
//!
//! * **Is anything arriving?** A relay that stopped relaying, a VLAN that
//!   stopped trunking, a firewall rule somebody added on Friday. The server's
//!   own logs cannot see any of it, because nothing reached the server to be
//!   logged, and its tables look quiet and healthy.
//! * **Is anything being answered?** A server that is up, listening, and
//!   refusing or failing everything looks exactly like one that is down --
//!   from the modem's side, it IS one that is down.
//!
//! Kept apart from the capture so it can be tested with numbers instead of
//! packets, and kept apart from the trap so a run with no SNMP target still
//! makes and logs the same judgement.

/// What one interface's last few minutes mean.
///
/// Judged per interface, not per plant. The two questions are the same as
/// they always were -- is anything arriving, and is it being answered -- but
/// "anything" means a different thing on a CMTS with four thousand modems
/// than on one with forty, and the answer has to be per interface or it is
/// wrong for one of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayVerdict {
    pub state: State,
    /// Seconds since a request last arrived here, when one ever has.
    pub idle_for: Option<u64>,
    /// What that interface was allowed.
    pub idle_allowed: u64,
}

/// Judges one interface.
///
/// Quiet is a SILENCE, not a low count: "at least one request every five
/// minutes" and "at least one every hour" are the same sentence with a
/// different number, and a count in a fixed window cannot say the second one.
///
/// An interface that has never sent a request is not quiet. It is one this
/// program has only just started watching, or one that is named in the
/// configuration and does not exist; either way, alarming about a plant that
/// has said nothing yet would fire on every start-up.
#[must_use]
pub fn judge_relay(
    requests: u64,
    replies: u64,
    idle_for: Option<u64>,
    idle_allowed: u64,
    min_answered: f64,
) -> RelayVerdict {
    let state = match idle_for {
        Some(idle) if idle > idle_allowed => State::Quiet,
        // Only judged once enough has arrived to make a ratio mean anything.
        // A ratio over three packets is noise, and reporting it would name
        // the wrong fault.
        Some(_) if requests >= 5 && answered(requests, replies) < min_answered => State::Unanswered,
        _ => State::Working,
    };
    RelayVerdict {
        state,
        idle_for,
        idle_allowed,
    }
}

/// The fraction answered, treating nothing asked as nothing to judge.
fn answered(requests: u64, replies: u64) -> f64 {
    if requests == 0 {
        return 1.0;
    }
    #[allow(clippy::cast_precision_loss, reason = "counts never reach 2^53")]
    {
        replies as f64 / requests as f64
    }
}

/// What the last window means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// Provisioning is happening.
    Working,
    /// Requests have all but stopped arriving.
    Quiet,
    /// Requests are arriving and too few are being answered.
    Unanswered,
}

impl State {
    /// The short word this appears under in the log and in a trap.
    #[must_use]
    pub const fn word(&self) -> &'static str {
        match self {
            Self::Working => "working",
            Self::Quiet => "quiet",
            Self::Unanswered => "unanswered",
        }
    }

    #[must_use]
    pub const fn is_trouble(&self) -> bool {
        !matches!(self, Self::Working)
    }
}

/// Remembers what has been said, so an afternoon-long outage is one trap and
/// not fifty.
#[derive(Debug)]
pub struct Repeats {
    after: u64,
    last: Option<(State, u64)>,
}

impl Repeats {
    #[must_use]
    pub const fn new(after: u64) -> Self {
        Self { after, last: None }
    }

    /// Whether this state should be sent now.
    ///
    /// A CHANGE always goes out, however recently something was said: going
    /// from quiet to unanswered is new information, and so is recovering.
    /// Only the same trouble repeating is held back.
    pub fn should_send(&mut self, state: &State, now: u64) -> bool {
        let send = match &self.last {
            None => state.is_trouble(),
            Some((was, _)) if was != state => true,
            Some((_, when)) => state.is_trouble() && now.saturating_sub(*when) >= self.after,
        };
        if send {
            self.last = Some((state.clone(), now));
        }
        send
    }
}

/// The worst of several interfaces' verdicts, which is what the plant's own
/// state is.
///
/// Worst, not an average: one CMTS out of twelve gone quiet is an outage for
/// everybody behind it, and averaging it away is how a monitor comes to say
/// "working" through a truck roll.
#[must_use]
pub fn worst(verdicts: &[RelayVerdict]) -> State {
    let mut out = State::Working;
    for v in verdicts {
        out = match (&out, &v.state) {
            (State::Quiet, _) | (_, State::Quiet) => State::Quiet,
            (State::Unanswered, _) | (_, State::Unanswered) => State::Unanswered,
            _ => State::Working,
        };
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_outage_lasting_an_afternoon_is_one_trap() {
        let mut r = Repeats::new(900);
        assert!(r.should_send(&State::Quiet, 0), "the first one goes");
        assert!(!r.should_send(&State::Quiet, 300), "not five minutes later");
        assert!(!r.should_send(&State::Quiet, 899));
        assert!(r.should_send(&State::Quiet, 900), "due again");
    }

    // Going from quiet to unanswered is new information, and so is recovering.
    #[test]
    fn a_change_of_state_always_goes_out() {
        let mut r = Repeats::new(900);
        assert!(r.should_send(&State::Quiet, 0));
        assert!(
            r.should_send(&State::Unanswered, 10),
            "a different fault is not a repeat"
        );
        assert!(
            r.should_send(&State::Working, 20),
            "recovery is worth knowing"
        );
        assert!(
            !r.should_send(&State::Working, 5000),
            "and is not repeated for ever"
        );
    }

    #[test]
    fn a_working_plant_says_nothing_to_start_with() {
        let mut r = Repeats::new(900);
        assert!(!r.should_send(&State::Working, 0));
        assert!(!r.should_send(&State::Working, 10_000));
    }

    fn verdict(idle: Option<u64>, allowed: u64, req: u64, rep: u64) -> RelayVerdict {
        judge_relay(req, rep, idle, allowed, 0.75)
    }

    // The whole point of doing this per interface. The same silence is normal
    // on one CMTS and an outage on another.
    #[test]
    fn the_same_silence_is_normal_on_one_cmts_and_an_outage_on_another() {
        // Four thousand modems: nothing for six minutes is wrong.
        assert_eq!(verdict(Some(360), 300, 0, 0).state, State::Quiet);
        // Forty modems, an hour of headroom: the same six minutes is Tuesday.
        assert_eq!(verdict(Some(360), 3_600, 0, 0).state, State::Working);
    }

    #[test]
    fn an_interface_at_its_limit_is_not_yet_quiet() {
        assert_eq!(verdict(Some(300), 300, 1, 1).state, State::Working);
        assert_eq!(verdict(Some(301), 300, 1, 1).state, State::Quiet);
    }

    // An interface that has never said anything is one this has only just
    // started watching, or one named in the file that does not exist.
    // Alarming on it would fire on every start-up.
    #[test]
    fn an_interface_that_has_never_spoken_is_not_an_outage() {
        assert_eq!(verdict(None, 300, 0, 0).state, State::Working);
    }

    #[test]
    fn an_interface_being_ignored_is_its_own_verdict() {
        assert_eq!(verdict(Some(10), 300, 100, 10).state, State::Unanswered);
        assert_eq!(verdict(Some(10), 300, 100, 90).state, State::Working);
        // And silence wins over it: a plant with nothing arriving is quiet,
        // whatever the ratio over the handful that did.
        assert_eq!(verdict(Some(9_000), 300, 100, 10).state, State::Quiet);
    }

    #[test]
    fn a_handful_of_requests_is_not_enough_to_call_it_unanswered() {
        assert_eq!(verdict(Some(10), 300, 4, 0).state, State::Working);
        assert_eq!(verdict(Some(10), 300, 5, 0).state, State::Unanswered);
    }

    // One CMTS out of twelve gone quiet is an outage for everybody behind it.
    // Averaging it away is how a monitor comes to say "working" through a
    // truck roll.
    #[test]
    fn one_bad_interface_decides_the_plant() {
        let mut all = vec![verdict(Some(1), 300, 100, 100); 11];
        assert_eq!(worst(&all), State::Working);
        all.push(verdict(Some(1), 300, 100, 5));
        assert_eq!(worst(&all), State::Unanswered);
        all.push(verdict(Some(9_000), 300, 0, 0));
        assert_eq!(worst(&all), State::Quiet, "silence outranks everything");
    }

    #[test]
    fn a_plant_with_no_interfaces_at_all_is_not_an_alarm() {
        assert_eq!(worst(&[]), State::Working);
    }
}
