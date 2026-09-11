// Copyright MMQR Development
//! `docsis_monitor` — watches a plant's provisioning traffic on the wire.
//!
//! It listens to an interface and counts the DHCP and TFTP packets crossing
//! it, in both directions and per destination, and says so in a log. When the
//! counts stop looking like a working plant it raises an SNMP trap.
//!
//! # Why a packet capture and not a database query
//!
//! The provisioning server already logs everything it answers, and the console
//! reads those tables. What neither can see is a request that never arrived.
//! A CMTS with a broken relay, a VLAN that stopped trunking, a firewall rule
//! somebody added on Friday: in every one of those the server's tables look
//! quiet and healthy, because nothing reached it to be logged. That is the
//! failure this program exists to catch, and the only place it is visible is
//! the wire.
//!
//! The second thing it watches is the answer. Discovers arriving with no
//! offers going back is a server that is up, listening, and refusing or
//! failing every request -- which reads as silence in exactly the same way.
//!
//! # What it needs to run
//!
//! A capture socket, which the kernel gives to root or to a binary with
//! `CAP_NET_RAW`. Without it the open fails with a message saying so rather
//! than a permission error out of a library.
//!
//! It never transmits on the interface it watches, and never writes to a
//! plant's database. Its only outputs are the log file and, if configured,
//! SNMP traps.

mod adapt;
mod alarm;
mod capture;
mod config;
mod counters;
mod email;
mod logfiles;
mod packet;
mod relays;
mod snmp;
mod version;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

/// Watch a DOCSIS plant's DHCP and TFTP traffic.
#[derive(Parser, Debug)]
#[command(name = "docsis_monitor", version, about, long_about = None)]
struct Cli {
    /// The configuration file.
    ///
    /// Defaults to the first of `~/config/docsis_monitor.json` and
    /// `/etc/docsis_monitor.json` that exists. Everything this program does --
    /// which interface to watch, what counts as trouble, where to send a trap
    /// -- is in there rather than on the command line, so a run under a
    /// supervisor is the same run an operator started by hand.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Stay in the foreground.
    ///
    /// This detaches by default: it is a monitor, and a monitor that stops
    /// when somebody closes a terminal is worse than no monitor, because the
    /// screen it was supposed to warn on stays quiet either way.
    #[arg(long)]
    nofork: bool,

    /// Read the configuration, check the interface and exit.
    ///
    /// For finding out whether this host can capture at all without leaving a
    /// process behind. It opens the capture, which is where the permission
    /// problem shows up, and closes it again.
    #[arg(long)]
    check: bool,

    /// Stop after this many seconds. Runs until interrupted when not given.
    #[arg(long, value_name = "SECONDS")]
    run_for: Option<u64>,

    /// Watch for this many minutes, then write down what idle looks like.
    ///
    /// An idle threshold is a claim about a CMTS interface: this one is never
    /// silent for more than five minutes, that one is properly silent for an
    /// hour. Guessing it produces a monitor that either cries wolf about a
    /// quiet interface every night or says nothing for an hour after a busy
    /// one falls over.
    ///
    /// This raises no alarms. It counts, and at the end it writes into the
    /// log what every relaying interface did and a `per_relay` block that can
    /// be pasted into the configuration -- with the evidence beside it, so
    /// somebody can see whether the window was long enough to be worth
    /// anything.
    #[arg(long, value_name = "MINUTES")]
    adaptation: Option<u64>,
}

fn main() -> Result<()> {
    // Before the parser: asking a binary when it was built must not depend on
    // the rest of the command line, on a readable configuration file, or on a
    // capture socket.
    crate::version::print_and_exit_if_requested();
    let cli = Cli::parse();

    // The configuration BEFORE the fork. A file that will not parse, or names
    // an interface this host does not have, is a mistake to answer on the
    // terminal somebody is standing at -- not in a log belonging to a process
    // that has already gone into the background and exited.
    let (cfg, from) = config::load(cli.config.as_deref())?;
    println!("configuration from {}", from.display());
    cfg.report_unknown();
    let iface = capture::find(&cfg.interface)?;
    println!(
        "watching {} ({})",
        iface.name,
        if iface.ips.is_empty() {
            "no address of its own".to_owned()
        } else {
            iface
                .ips
                .iter()
                .map(|n| n.ip().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );

    // Opening the capture BEFORE the fork, and throwing it away again.
    //
    // Not having permission to capture is the failure everybody meets first,
    // and it is a failure with a fix somebody types. Discovering it after
    // detaching would put that message in a log file, leave the command
    // returning 0, and leave an operator believing a monitor is running.
    //
    // The socket is opened a second time in the child rather than carried
    // across the fork. A descriptor would survive it, but relying on which
    // ones a daemonising library keeps is the kind of thing that works until
    // the library is upgraded; opening twice costs one syscall on a path that
    // runs once.
    let probe = capture::open(&iface, &cfg)?;
    drop(probe);
    if cli.check {
        println!("capture opened; this host can watch that interface");
        return Ok(());
    }

    if !cli.nofork && !cfg.nofork {
        go_to_background()?;
    }

    // After the fork, both because the PID file must name the process that
    // survives and because the heartbeat thread would not: threads do not
    // cross a fork. Held for the life of the program -- dropping the guard
    // removes the PID file.
    let _logs = logfiles::start()?;

    let rx = capture::open(&iface, &cfg)?;
    capture::run(rx, &cfg, cli.run_for, cli.adaptation);
    Ok(())
}

/// Detaches from the terminal, leaving the watching to a process of its own.
///
/// `~/logs` must exist first. Detaching without it would send every word this
/// program says to `/dev/null`, and a monitor nobody can read is worse than no
/// monitor at all: it is a monitor everybody believes is watching. The two
/// ways out are named rather than chosen here, because both are somebody's
/// real intention.
fn go_to_background() -> Result<()> {
    let Some(dir) = logfiles::dir().filter(|d| d.is_dir()) else {
        let where_ =
            logfiles::dir().map_or_else(|| "~/logs".to_owned(), |d| d.display().to_string());
        anyhow::bail!(
            "there is no {where_} directory, so a background run would have nowhere \
             to say anything and nothing to write a PID file to. Either `mkdir \
             {where_}` or pass --nofork to keep it on this terminal."
        );
    };
    // On the terminal, before the fork takes it away. Without this the command
    // returns in silence and the operator has to guess that there is a log and
    // where it is.
    println!(
        "going into the background; logging to {}",
        dir.join(logfiles::LOG_FILE).display()
    );
    let _ = std::io::Write::flush(&mut std::io::stdout());

    // The working directory is kept rather than changed to `/`. A relative
    // path on this program's command line -- `--config ./docsis_monitor.json`
    // -- is an ordinary thing to type, and a process that moved out from under
    // it would answer with a file-not-found naming a path that exists.
    let here = std::env::current_dir().context("finding the current directory")?;
    daemonize::Daemonize::new()
        .working_directory(&here)
        .umask(0o027)
        .start()
        .context("detaching from the terminal")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_is_valid() {
        Cli::command().debug_assert();
    }

    // Every setting lives in the file. The command line says which file, and
    // what to do about this one run.
    #[test]
    fn the_command_line_carries_no_settings() {
        for gone in ["--interface", "--snmp-target", "--threshold", "--community"] {
            assert!(
                Cli::try_parse_from(["docsis_monitor", gone, "x"]).is_err(),
                "{gone} must not be an argument; settings belong in the file"
            );
        }
    }
}
