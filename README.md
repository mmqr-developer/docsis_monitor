docsis_monitor
==============

Watches a DOCSIS plant's provisioning traffic on the wire, and says something
when it stops looking like a working plant.

    docsis_monitor              # detaches, logs to ~/logs/docsis_monitor.log
    docsis_monitor --nofork     # stays on the terminal
    docsis_monitor --check      # reads the config, opens the capture, exits
    docsis_monitor --version    # 1788814003 2026-9-7 14:46:43

Why it exists
-------------

The provisioning server logs everything it answers, and the console reads
those tables. What neither can see is a request that never arrived.

A CMTS with a broken relay, a VLAN that stopped trunking, a firewall rule
somebody added on Friday: in every one of those the server's tables look quiet
and healthy, because nothing reached the server to be logged. That is the
failure this catches, and the only place it is visible is the wire.

The second thing it watches is the answer. Discovers arriving with no offers
going back is a server that is up, listening, and refusing or failing every
request — which, from a modem's side, is a server that is down.

What it does
------------

Counts the DHCP and TFTP packets crossing one interface, in both directions,
per conversation and per CMTS. Every `report_every` seconds it writes what it
saw to the log and judges each interface:

* **quiet** — nothing has arrived from that CMTS for longer than it is
  allowed to be silent.
* **unanswered** — requests are arriving and fewer than `min_answered` of
  them are being answered.
* **working** — neither.

The plant's state is the worst of them. One CMTS out of twelve gone quiet is
an outage for everybody behind it, and a threshold over the whole plant
averages that away.

Per CMTS, because a plant is not one thing. One interface carries several
thousand modems and should never be silent for five minutes; another carries
forty and is properly silent for an hour. One number is wrong for both: set
for the busy one it cries wolf about the quiet one every night, and set for
the quiet one it says nothing for an hour after the busy one falls over.

It also times the answers. Counting replies is not knowing requests were
answered: two thousand of each in a window is a plant answering everything in
four milliseconds, or one answering half of them twice, four seconds late.
Both sides cross the interface, so a request and its reply are matched on
their transaction id and the gap between them is the server's response time
as the CMTS experiences it.

TFTP is counted and not alarmed on. It is far quieter than DHCP by nature —
the equipment behind a modem never touches it, so a plant fetches a config
when a modem boots and not again.

A change of state tells whoever is configured: an SNMPv2c trap to every trap
receiver, and mail to every recipient. The same trouble is not repeated for
`resend_after` seconds; a change always goes out, including the recovery.

With neither configured it says nothing at all — the state is already on the
report line, and a monitor that logs its own inaction every window is a
monitor whose log nobody reads.

The per-destination counts are what make an alarm actionable: on a plant with
four relays, three still talking and one silent names the one to go and look
at.

Working out the thresholds
--------------------------

Do not guess them.

    docsis_monitor --adaptation 60

Watches for an hour, raises no alarms, and writes into the log what every
relaying interface did — how many requests, the longest silence between two of
them — with a suggested `idle_seconds` and the arithmetic behind it. The last
thing it prints is a `per_relay` block that can be pasted into the
configuration.

It sees one window of one day. A plant is busiest in the evening and quietest
at four in the morning, and an hour at noon says nothing about either; the
evidence is printed beside every suggestion so somebody can judge whether the
window was long enough. Where it saw too little to say anything honest — one
request, or none — it says so instead of suggesting a number, because writing
today's outage into the configuration as tomorrow's normal is worse than
having no threshold at all.

Configuration
-------------

Everything is in `~/config/docsis_monitor.json`, or `/etc/docsis_monitor.json`
for a system service. See `docsis_monitor.example.json`, which is checked by
the test suite against the code that reads it. A key this program does not
know is printed at startup rather than refused — on a monitor, a setting that
silently does nothing is an alarm that never fires, and that looks exactly
like a plant that is working.

Running it
----------

A capture socket belongs to root or to a binary holding `CAP_NET_RAW`:

    sudo setcap cap_net_raw,cap_net_admin=eip /path/to/docsis_monitor

`--check` is the way to find out whether a host can capture at all without
leaving a process behind. The capture is opened before the fork as well, so a
permission problem is answered on the terminal rather than in a log file
belonging to a process that has already exited.

It never transmits on the interface it watches and never writes to a plant's
database. Its only outputs are the log and, if configured, traps.

Mail
----

A trap goes to a network management platform, which not every plant has. A
mail relay, every plant has.

The subject carries the whole finding — which host, which state, and the
counts behind it — because that is all a phone shows. A subject reading
"DOCSIS alert" makes somebody open the mail to find out whether to get up.

Plain SMTP, no STARTTLS. Adding it means a TLS stack to keep patched on hosts
nobody logs in to, in a program whose point is to run unattended. So this is
for a relay on a network you trust, which is the ordinary shape for alerting.
`AUTH PLAIN` is there because some relays insist on it, and the password then
crosses the wire in clear text; if the relay is not on a trusted network,
leave it out and let the relay accept the mail unauthenticated.

Nothing is queued and nothing is retried. A failed send is logged with the
subject, so the finding survives even though the message did not, and the next
window tries again.

Traps
-----

Under `1.3.6.1.4.1.99999`:

    .1  quiet        nothing is arriving
    .2  unanswered   arriving, and not being answered
    .3  recovered    working again

Each carries the host name, the interface, the state, the requests, replies
and TFTP reads counted, the window length in seconds, and the busiest
destination — so an alert says where to look without anybody logging in.

Building
--------

    ./build.sh            # checks, then a static build with the time compiled in
    ./build.sh --deploy   # ...and send it to the distribution server

Statically linked against musl, like every other tool here, because the
distribution server refuses a dynamically linked binary and these land on
hosts whose libc nobody has checked.

Not libpcap
-----------

The capture is an `AF_PACKET` socket, which is what libpcap opens on Linux,
reached through `pnet_datalink` so no C library is involved. Two reasons, both
concrete: libpcap's headers are not installed on the machine this was written
on, and linking it into a static musl binary needs a musl build of libpcap,
which is a second toolchain to install and keep.

What is given up is the kernel-side BPF filter. Filtering happens in this
process instead, which costs one function call per frame and no syscalls; a
provisioning interface carries thousands of packets a second, not millions.
