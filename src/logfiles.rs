// Copyright MMQR Development
//! A PID file and a log file in `~/logs`, when that directory exists.
//!
//! Matching what `docsis_admin_p7775` does, and for the same reason: this
//! program is normally left running for hours against a test database, and a
//! terminal that has since been closed is a poor place for its only record of
//! what it did.
//!
//! `~/logs` existing is the switch. Nothing is created if it does not, and the
//! program runs exactly as it always has, printing to the terminal. That keeps
//! a one-off `--dry-run` on a fresh machine from quietly writing files
//! somewhere the person running it is not looking.
//!
//! # Why the real file descriptors
//!
//! Both streams are redirected with `dup2`, not by routing this program's own
//! `println!` calls somewhere else. The difference shows up exactly when it
//! matters: a panic message, a MySQL driver warning and anything a library
//! writes to stderr all go to descriptor 2 without asking this code first. A
//! redirect that only covered our own prints would look like it worked until
//! the run went wrong.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use nix::sys::stat::utimes;
use nix::sys::time::TimeVal;

/// The name both files carry, without an extension.
///
/// One stem, unlike the sibling programs in this repository, whose PID file is
/// spelled for the watchdog and whose log is spelled for a person. This
/// program is named the same way in both places, so there is nothing to
/// choose between.
const STEM: &str = "docsis_monitor";

/// The log file's name, for the line printed on the terminal before a run
/// detaches and takes the terminal away.
pub const LOG_FILE: &str = "docsis_monitor.log";

/// How often the PID file's timestamp is refreshed.
///
/// The same minute `docsis_admin_p7775` uses, and for the same reason. A
/// watchdog allowing for a missed tick should treat anything under about three
/// minutes as healthy rather than alerting on the first one.
pub const HEARTBEAT: Duration = Duration::from_secs(60);

/// A PID file that removes itself.
///
/// A process that is killed outright leaves the file behind, which is why the
/// PID inside it is the thing to check rather than the file's existence.
#[derive(Debug)]
pub struct PidFile(PathBuf);

impl Drop for PidFile {
    fn drop(&mut self) {
        // Nothing useful to do if this fails, and by now stderr may be the log
        // file we are about to stop writing to.
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Where this user's logs live, whether or not it exists.
#[must_use]
pub fn dir() -> Option<PathBuf> {
    std::env::home_dir().map(|h| h.join("logs"))
}

/// Redirects both output streams into `~/logs` and writes a PID file there.
///
/// Returns `None`, having changed nothing, when there is no `~/logs`
/// directory. Returns the guard and the log path otherwise; hold the guard for
/// the life of the program, since dropping it removes the PID file.
///
/// Errors are real errors rather than a silent fall back to the terminal: a
/// `~/logs` that exists but cannot be written to is a broken setup, and
/// discovering that hours later from an empty file is worse than not starting.
pub fn capture() -> Result<Option<(PidFile, PathBuf)>> {
    capture_in(dir())
}

/// [`capture`], with the directory supplied.
///
/// A test cannot move `$HOME` without `unsafe`, which this crate forbids, and
/// a test that reimplemented the "does it exist" rule would prove nothing
/// about the code that ships.
pub fn capture_in(dir: Option<PathBuf>) -> Result<Option<(PidFile, PathBuf)>> {
    let Some(dir) = dir.filter(|d| d.is_dir()) else {
        return Ok(None);
    };
    let log = dir.join(format!("{STEM}.log"));
    let pid = dir.join(format!("{STEM}.pid"));

    // Appended to, not truncated: a run started an hour after the last one
    // should not throw away what the last one recorded.
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .with_context(|| format!("opening {}", log.display()))?;

    // On the terminal, before the redirect takes it away. Without this a run
    // that fails immediately -- a --dry-run against the wrong database, say --
    // prints nothing at all where the person is looking, and leaves them to
    // guess that there is a file and where it is.
    eprintln!("logging to {}", log.display());

    redirect(&file, &log)?;
    let guard = write_pid(&pid)?;
    start_heartbeat(pid);
    Ok(Some((guard, log)))
}

/// [`capture`], plus the banner that says where the output went.
///
/// A log file that is appended to across runs needs a mark between them, and
/// the build stamp is the useful thing to put in it: the question asked of an
/// old log is usually which build wrote it.
pub fn start() -> Result<Option<PidFile>> {
    let Some((guard, path)) = capture()? else {
        return Ok(None);
    };
    // Into the log, not the terminal: a file appended to across runs needs a
    // mark between them, and the build stamp and pid are the useful things to
    // put in it. What an old log gets asked is which build wrote it.
    //
    // The terminal was told where to look before the redirect happened, in
    // `capture_in`.
    let _ = &path;
    println!(
        "--- docsis_monitor {} pid {} ---",
        crate::version::build_stamp(),
        std::process::id()
    );
    Ok(Some(guard))
}

/// Points descriptors 1 and 2 at `file`.
fn redirect(file: &File, log: &Path) -> Result<()> {
    // Flushed first: anything already buffered belongs on the terminal the
    // program was started from, not at the top of the log file.
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    let fd = file.as_fd();
    nix::unistd::dup2_stdout(fd)
        .with_context(|| format!("redirecting stdout to {}", log.display()))?;
    nix::unistd::dup2_stderr(fd)
        .with_context(|| format!("redirecting stderr to {}", log.display()))?;
    Ok(())
}

/// Writes this process's id, replacing whatever was there.
fn write_pid(path: &Path) -> Result<PidFile> {
    let mut f = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    writeln!(f, "{}", std::process::id()).with_context(|| format!("writing {}", path.display()))?;
    Ok(PidFile(path.to_owned()))
}

/// Stamps the PID file every [`HEARTBEAT`] until the process exits.
///
/// The PID file already tells a watchdog which process to look for, but its
/// timestamp is the moment this run started -- so on its own it answers "when
/// did this begin", never "is it still going". Touching it on a timer turns a
/// file the watchdog is already reading into a heartbeat, with no new port, no
/// new endpoint and nothing to authenticate.
///
/// What a fresh timestamp proves is that the process exists and is still
/// scheduling threads. That is what catches a crash, an OOM kill or a machine
/// that rebooted without bringing this back. It does **not** prove the program
/// is doing useful work: one blocked on a wedged MySQL server goes on stamping
/// happily. A watchdog restarting on this alone must not conclude more.
///
/// The timestamp is touched and the contents left alone. The pid cannot change
/// while the process lives, and rewriting would give a watchdog reading at that
/// instant the chance to see a half-written file.
fn start_heartbeat(path: PathBuf) {
    std::thread::spawn(move || {
        // A PID file deleted under us logs once rather than once a minute for
        // ever: this goes to a log an operator has to read, and a line a minute
        // would bury everything else in it within a day.
        let mut failing = false;
        loop {
            std::thread::sleep(HEARTBEAT);
            match touch(&path) {
                Ok(()) => {
                    if failing {
                        failing = false;
                        println!("pid file heartbeat recovered: {}", path.display());
                    }
                }
                Err(e) => {
                    if !failing {
                        failing = true;
                        eprintln!(
                            "could not stamp {} ({e}); a watchdog will read this process as dead",
                            path.display()
                        );
                    }
                }
            }
        }
    });
}

/// Sets a file's access and modification times to now, leaving it otherwise
/// untouched.
fn touch(path: &Path) -> Result<()> {
    let since = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let now = TimeVal::new(
        i64::try_from(since.as_secs()).unwrap_or(i64::MAX),
        i64::from(since.subsec_micros()),
    );
    utimes(path, &now, &now).with_context(|| format!("stamping {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Both files carry the program's own name. A watchdog looks for the PID
    // file by a name it was given, and a person greps ~/logs for the project;
    // here those are the same word, so there is nothing to choose between.
    #[test]
    fn both_files_are_named_after_the_program() {
        assert_eq!(STEM, "docsis_monitor");
        assert_eq!(LOG_FILE, format!("{STEM}.log"));
    }

    #[test]
    fn nothing_happens_without_a_logs_directory() {
        // The switch is the directory existing. A machine without one gets the
        // behaviour it has always had, and nothing appears anywhere -- which
        // is the half worth asserting, since a redirect that fired here would
        // send the run's output somewhere nobody is looking.
        let missing = tempdir("absent").join("logs");
        assert!(!missing.exists());
        let got = capture_in(Some(missing.clone())).expect("no directory is not an error");
        assert!(got.is_none(), "something was created without ~/logs");
        assert!(!missing.exists(), "capture_in created the directory itself");
    }

    #[test]
    fn a_pid_file_is_written_and_removed_again() {
        // Only the PID half is exercised here: redirecting descriptors 1 and 2
        // would take the test harness's own output with it.
        let dir = tempdir("pid");
        let path = dir.join(format!("{STEM}.pid"));
        {
            let _guard = write_pid(&path).expect("write the pid file");
            let text = std::fs::read_to_string(&path).expect("read it back");
            assert_eq!(
                text.trim().parse::<u32>().expect("a number"),
                std::process::id(),
                "the file must carry this process's id, not something else"
            );
        }
        assert!(!path.exists(), "the guard did not remove the pid file");
    }

    #[test]
    fn a_stamp_moves_the_timestamp_forward_without_changing_the_file() {
        // What a watchdog reads. The contents must survive untouched: the pid
        // cannot change while the process lives, and a rewrite would give a
        // watchdog reading at that instant a half-written file.
        let dir = tempdir("touch");
        let path = dir.join("stamped");
        std::fs::write(&path, "4321\n").expect("write");

        let old = TimeVal::new(1_000_000_000, 0);
        utimes(&path, &old, &old).expect("age the file");
        let before = std::fs::metadata(&path)
            .expect("stat")
            .modified()
            .expect("mtime");

        touch(&path).expect("stamp it");
        let after = std::fs::metadata(&path)
            .expect("stat")
            .modified()
            .expect("mtime");

        assert!(
            after > before,
            "the timestamp did not move: {before:?} -> {after:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read back"),
            "4321\n",
            "stamping must not rewrite the file"
        );
    }

    #[test]
    fn the_heartbeat_is_the_minute_the_other_programs_use() {
        // A watchdog is configured once for every program it watches. Two of
        // them disagreeing about the interval is how one gets declared dead.
        assert_eq!(HEARTBEAT, Duration::from_secs(60));
    }

    fn tempdir(what: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fdsl-{}-{what}", std::process::id()));
        std::fs::create_dir_all(&d).expect("temp dir");
        d
    }
}
