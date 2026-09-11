// Copyright MMQR Development
//! Telling somebody by mail.
//!
//! A trap goes to a network management platform, which not every plant has. A
//! mail server, every plant has. This is the same finding as the trap, in a
//! form somebody reads on a phone at two in the morning.
//!
//! # Plain `SMTP`, and what that means
//!
//! `EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`, `QUIT`. No `STARTTLS`: adding it
//! means a TLS stack, which is a large dependency in a program whose whole
//! point is to keep running unattended, and which would have to be kept
//! patched on hosts nobody logs in to.
//!
//! So this is for a relay on a network you trust -- the ordinary shape for
//! alerting, where the monitor and the relay are two machines in the same
//! room. `AUTH PLAIN` is supported because some relays insist on it, and the
//! password crosses the wire in clear text when it is used. That is said here
//! and in the example configuration rather than left for somebody to find
//! out: if the relay is not on a trusted network, do not put a password in
//! this file.
//!
//! # What it is not
//!
//! It is not a mail client. It does not queue, retry, or handle a bounce. A
//! send that fails is reported in the log and the next window tries again,
//! which for an alert is the right shape: an alert that arrives late is worse
//! than one that arrives twice.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::config::Smtp;

/// How long any one step of the conversation may take.
///
/// A relay that accepts the connection and then says nothing would otherwise
/// hold this thread for ever, and the thread it holds is the one doing the
/// watching.
const STEP: Duration = Duration::from_secs(10);

/// The subject and body of one alert.
///
/// Built apart from the sending so it can be read in a test without a mail
/// server, and so the same words go into the log if a send fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub subject: String,
    pub body: String,
}

/// Writes the alert.
///
/// The subject carries the whole finding, because that is all a phone shows:
/// which host, which state, and the counts behind it. A subject reading
/// "DOCSIS alert" makes somebody open the mail to find out whether to get up.
#[must_use]
pub fn compose(
    prefix: &str,
    host: &str,
    interface: &str,
    state: &str,
    w: crate::counters::Window,
    window_secs: u64,
    busiest: &str,
) -> Message {
    let headline = match state {
        "quiet" => format!("no DHCP arriving on {host}"),
        "unanswered" => format!("DHCP not being answered on {host}"),
        _ => format!("DHCP back to normal on {host}"),
    };
    let subject = format!(
        "{prefix} {headline} — {} requests, {} replies in {window_secs}s",
        w.requests, w.replies
    );
    let body = format!(
        "{headline}\n\
         \n\
         host        {host}\n\
         interface   {interface}\n\
         state       {state}\n\
         window      {window_secs} seconds\n\
         \n\
         requests    {}\n\
         replies     {}\n\
         answered    {:.0}%\n\
         tftp reads  {}\n\
         busiest     {busiest}\n\
         \n\
         Counted on the wire by docsis_monitor. Requests are what reached this\n\
         interface; a relay that has stopped relaying leaves nothing in the\n\
         provisioning server's own logs, because nothing reached it to be logged.\n",
        w.requests,
        w.replies,
        w.answered() * 100.0,
        w.tftp_reads,
    );
    Message { subject, body }
}

/// Sends one message to every configured recipient, in one conversation.
pub fn send(cfg: &Smtp, m: &Message) -> std::io::Result<()> {
    let to = (cfg.server.as_str(), cfg.port);
    let stream = TcpStream::connect(to)?;
    stream.set_read_timeout(Some(STEP))?;
    stream.set_write_timeout(Some(STEP))?;
    let mut sock = BufReader::new(stream);

    expect(&mut sock, b'2')?; // the greeting
    say(&mut sock, &format!("EHLO {}\r\n", cfg.helo()))?;
    expect(&mut sock, b'2')?;

    if let (Some(user), Some(pass)) = (&cfg.username, &cfg.password) {
        // AUTH PLAIN is authzid NUL authcid NUL password, base64. In clear
        // text on a plain connection; see the module header.
        let secret = format!("\0{user}\0{pass}");
        say(
            &mut sock,
            &format!("AUTH PLAIN {}\r\n", base64(secret.as_bytes())),
        )?;
        expect(&mut sock, b'2')?;
    }

    say(&mut sock, &format!("MAIL FROM:<{}>\r\n", cfg.from))?;
    expect(&mut sock, b'2')?;
    for rcpt in &cfg.to {
        say(&mut sock, &format!("RCPT TO:<{rcpt}>\r\n"))?;
        expect(&mut sock, b'2')?;
    }
    say(&mut sock, "DATA\r\n")?;
    expect(&mut sock, b'3')?;
    say(&mut sock, &data(cfg, m))?;
    expect(&mut sock, b'2')?;
    // QUIT is sent and its answer is not waited for. The mail is accepted at
    // the end of DATA; a relay that hangs up rudely afterwards has still
    // taken it, and waiting would be ten seconds of the watching thread.
    let _ = say(&mut sock, "QUIT\r\n");
    Ok(())
}

/// The message itself, headers and all, ending with the lone dot.
///
/// Dot-stuffed: a body line that is a single dot would otherwise end the
/// message early, and the counts below could produce one on a day nobody
/// planned for.
#[must_use]
pub fn data(cfg: &Smtp, m: &Message) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = write!(out, "From: {}\r\n", cfg.from);
    let _ = write!(out, "To: {}\r\n", cfg.to.join(", "));
    let _ = write!(out, "Subject: {}\r\n", m.subject);
    out.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    out.push_str("\r\n");
    for line in m.body.lines() {
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str(".\r\n");
    out
}

fn say(sock: &mut BufReader<TcpStream>, what: &str) -> std::io::Result<()> {
    sock.get_mut().write_all(what.as_bytes())?;
    sock.get_mut().flush()
}

/// Reads a reply and checks its first digit.
///
/// A reply can be several lines: `250-SIZE` then `250 HELP`. The last one has
/// a space after the code rather than a hyphen, which is the only way to know
/// the relay has finished talking.
fn expect(sock: &mut BufReader<TcpStream>, want: u8) -> std::io::Result<()> {
    loop {
        let mut line = String::new();
        if sock.read_line(&mut line)? == 0 {
            return Err(std::io::Error::other("the mail server hung up"));
        }
        let b = line.as_bytes();
        if b.first() != Some(&want) {
            return Err(std::io::Error::other(format!(
                "the mail server said: {}",
                line.trim_end()
            )));
        }
        if b.get(3) != Some(&b'-') {
            return Ok(());
        }
    }
}

/// Base64, for `AUTH PLAIN`.
#[must_use]
fn base64(raw: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in raw.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= c.len() {
                out.push(char::from(A[((n >> (18 - 6 * i)) & 0x3F) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::counters::Window;
    use std::io::Read;
    use std::net::TcpListener;

    fn smtp(at: std::net::SocketAddr) -> Smtp {
        Smtp {
            server: at.ip().to_string(),
            port: at.port(),
            from: "monitor@example.com".to_owned(),
            to: vec![
                "noc@example.com".to_owned(),
                "oncall@example.com".to_owned(),
            ],
            subject_prefix: "[docsis]".to_owned(),
            username: None,
            password: None,
            helo_name: None,
        }
    }

    fn window() -> Window {
        Window {
            requests: 0,
            replies: 0,
            tftp_reads: 0,
            tftp_sends: 0,
        }
    }

    // A phone shows the subject and nothing else. "DOCSIS alert" makes
    // somebody open the mail to find out whether to get up.
    #[test]
    fn the_subject_carries_the_whole_finding() {
        let m = compose("[docsis]", "prov-1", "eth0", "quiet", window(), 300, "none");
        assert!(m.subject.starts_with("[docsis] "), "{}", m.subject);
        assert!(
            m.subject.contains("no DHCP arriving on prov-1"),
            "{}",
            m.subject
        );
        assert!(m.subject.contains("0 requests"), "{}", m.subject);
        assert!(m.subject.contains("300s"), "{}", m.subject);
    }

    #[test]
    fn each_state_gets_its_own_headline() {
        let w = Window {
            requests: 90,
            replies: 2,
            ..window()
        };
        let un = compose("[d]", "prov-1", "eth0", "unanswered", w, 300, "10.0.0.1");
        assert!(un.subject.contains("not being answered"), "{}", un.subject);
        assert!(un.body.contains("10.0.0.1"), "the busiest is in the body");
        assert!(un.body.contains("answered    2%"), "{}", un.body);

        let ok = compose("[d]", "prov-1", "eth0", "working", w, 300, "10.0.0.1");
        assert!(ok.subject.contains("back to normal"), "{}", ok.subject);
    }

    // A body line that is a single dot ends the message early. The counts
    // could produce one on a day nobody planned for.
    #[test]
    fn a_line_that_is_a_dot_is_stuffed() {
        let cfg = smtp("127.0.0.1:1".parse().expect("an address"));
        let m = Message {
            subject: "s".to_owned(),
            body: "one\n.\n.hidden\ntwo".to_owned(),
        };
        let d = data(&cfg, &m);
        assert!(d.contains("\r\n..\r\n"), "a lone dot is stuffed:\n{d}");
        assert!(d.contains("\r\n..hidden\r\n"), "so is a leading one");
        assert!(d.ends_with("\r\n.\r\n"), "and the real terminator is last");
    }

    #[test]
    fn the_headers_name_every_recipient() {
        let cfg = smtp("127.0.0.1:1".parse().expect("an address"));
        let d = data(
            &cfg,
            &Message {
                subject: "s".to_owned(),
                body: "b".to_owned(),
            },
        );
        assert!(d.contains("From: monitor@example.com\r\n"));
        assert!(d.contains("To: noc@example.com, oncall@example.com\r\n"));
        assert!(d.contains("Subject: s\r\n"));
    }

    #[test]
    fn base64_matches_the_examples_everybody_checks_against() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        // AUTH PLAIN is NUL-separated, which is exactly the case a text-only
        // encoder gets wrong.
        assert_eq!(base64(b"\0user\0pass"), "AHVzZXIAcGFzcw==");
    }

    /// A mail server that says yes to everything, and hands back the whole
    /// conversation it heard.
    fn fake_relay(script_ok: bool) -> (std::net::SocketAddr, std::thread::JoinHandle<String>) {
        let l = TcpListener::bind("127.0.0.1:0").expect("a local port");
        let at = l.local_addr().expect("its address");
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().expect("a connection");
            let mut heard = String::new();
            let reply = |s: &mut TcpStream, what: &str| {
                let _ = s.write_all(what.as_bytes());
            };
            reply(&mut s, "220 fake ESMTP\r\n");
            let mut buf = [0u8; 4096];
            let mut in_data = false;
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                heard.push_str(&chunk);
                for line in chunk.split("\r\n") {
                    if line.is_empty() {
                        continue;
                    }
                    if in_data {
                        if line == "." {
                            in_data = false;
                            reply(
                                &mut s,
                                if script_ok {
                                    "250 queued\r\n"
                                } else {
                                    "451 no\r\n"
                                },
                            );
                        }
                        continue;
                    }
                    if line.starts_with("EHLO") {
                        // Multi-line, which is what every real relay sends and
                        // the shape a naive reader stops halfway through.
                        reply(&mut s, "250-fake\r\n250-SIZE 1000000\r\n250 HELP\r\n");
                    } else if line.starts_with("DATA") {
                        in_data = true;
                        reply(&mut s, "354 go ahead\r\n");
                    } else if line.starts_with("QUIT") {
                        reply(&mut s, "221 bye\r\n");
                        return heard;
                    } else {
                        reply(&mut s, "250 ok\r\n");
                    }
                }
            }
            heard
        });
        (at, h)
    }

    // The whole conversation, against something that answers the way a relay
    // answers -- including a multi-line EHLO reply, which is the shape a
    // reader that stops at the first line gets wrong.
    #[test]
    fn a_message_goes_through_a_relay_in_the_right_order() {
        let (at, h) = fake_relay(true);
        let cfg = smtp(at);
        let m = compose("[docsis]", "prov-1", "eth0", "quiet", window(), 300, "none");
        send(&cfg, &m).expect("the relay took it");
        let heard = h.join().expect("the relay thread");

        let order = [
            "EHLO",
            "MAIL FROM:<monitor@example.com>",
            "RCPT TO:<noc@example.com>",
            "RCPT TO:<oncall@example.com>",
            "DATA",
            "Subject: [docsis]",
            "\r\n.\r\n",
            "QUIT",
        ];
        let mut at_pos = 0;
        for step in order {
            let found = heard[at_pos..]
                .find(step)
                .unwrap_or_else(|| panic!("{step} is missing or out of order in:\n{heard}"));
            at_pos += found + step.len();
        }
        assert!(!heard.contains("AUTH"), "no password was configured");
    }

    #[test]
    fn a_relay_that_refuses_is_an_error_and_not_a_silent_success() {
        let (at, h) = fake_relay(false);
        let e = send(
            &smtp(at),
            &Message {
                subject: "s".to_owned(),
                body: "b".to_owned(),
            },
        )
        .expect_err("451 is a refusal");
        assert!(e.to_string().contains("451"), "{e}");
        let _ = h.join();
    }

    #[test]
    fn a_password_sends_auth_plain_before_the_envelope() {
        let (at, h) = fake_relay(true);
        let mut cfg = smtp(at);
        cfg.username = Some("user".to_owned());
        cfg.password = Some("pass".to_owned());
        send(
            &cfg,
            &Message {
                subject: "s".to_owned(),
                body: "b".to_owned(),
            },
        )
        .expect("the relay took it");
        let heard = h.join().expect("the relay thread");
        let auth = heard
            .find("AUTH PLAIN AHVzZXIAcGFzcw==")
            .expect("AUTH is sent");
        let mail = heard.find("MAIL FROM").expect("the envelope follows");
        assert!(auth < mail, "AUTH must come before the envelope");
    }
}
