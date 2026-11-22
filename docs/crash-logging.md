# Crash logging for the faulty core

`faultlab-crashd` follows the journal and writes one folder per incident under
`/var/log/faultlab/crashes`.  On the reference host the configured fault core
is CPUs **2 and 8** (physical core 2); the collector uses the CPU set from
`/etc/faultlab/config`, not a hard-coded core number.

## What is captured

| Source | Stored when |
|---|---|
| Machine-check / EDAC / hardware error | always; annotated with the CPU from the message |
| Kernel panic, oops, BUG, lockup, RCU stall, hung task | fault-core CPU named; any critical kernel crash while `mode=lab`; a panic with no CPU |
| `segfault` / `traps` kernel line | fault-core CPU named |
| Coredump | cgroup under `/faultlab.slice`, or the process was allowed on a fault CPU while the core is online |
| pstore panic record | record names a fault CPU, or is a panic |
| kdump `vmcore` | a new `/var/crash/*/vmcore` is present |

rasdaemon tracepoint management lines (`Enabled event mce:mce_record`, CXL
event enable/disable) are control-plane messages and are ignored.  Real error
records, including CXL event payloads, are unchanged.

Each incident folder contains:

```
README.txt        human summary and inspection commands
incident.json     machine-readable record
journal.txt       kernel context around the event
dmesg.txt         ring buffer at capture time
ras.txt           ras-mc-ctl --summary/--errors (system service)
topology.txt      lscpu, fault CPU state, isolation, mode
processes.txt     tasks sampled on fault-core CPUs
sensors.txt       temperatures at capture time
occurrences.jsonl repeated events merged into this folder
coredump/         coredumpctl info + backtrace, no environment block
checksums.sha256  hashes of every file
```

`index.jsonl` is the append-only index; `latest` points at the newest incident.
Repeated identical events within the dedup window update the existing folder
(`occurrences.jsonl`) instead of creating noise.

## Commands

```bash
sudo faultlab-crashes status
sudo faultlab-crashes list
sudo faultlab-crashes show latest
sudo faultlab-crashes path latest
sudo faultlab-crashes verify latest
sudo faultlab-crashes export latest --out /root/crash.tar.gz
sudo faultlab-crashes prune --keep 100 --max-mb 2048 --dry-run
```

`faultlab-crashes` accepts `--dir PATH` before or after the subcommand.  A
non-root run defaults to `~/faultlab-crashes`; root defaults to
`/var/log/faultlab/crashes`.

## Attribution labels

- **direct** — kernel evidence names a fault-core CPU, or the coredump cgroup is
  `/faultlab.slice/...`.
- **possible** — no CPU was named, but the event is a machine check or panic, a
  critical kernel crash happened during a lab session, or the process was
  allowed on a fault CPU while the core was online.
- **other-cpu** — a machine-check event named another CPU; kept because the
  package and shared cache are still relevant to comparison.
- **none** — context only; normally not stored unless collection is widened.

The QA feed context prints the configured core only when a matched CPU or a
`faultlab.slice` coredump makes the attribution direct; otherwise it says
`fault_core=unattributed` and keeps the configured label separately.

## Service modes

The system service is installed by `apply.sh`:

```bash
sudo systemctl status faultlab-crashd
sudo journalctl -u faultlab-crashd -n 50
```

It runs in `system.slice` and is pinned to `SAFE_CPUS` by the drop-in written by
`apply.sh`, so the collector itself never runs on the fault core.  The boot-time
retirement service and the collector are independent.

Where root is not available yet, a per-user collector can be started without
sudo:

```bash
./install-user.sh                 # writes ~/faultlab-crashes
faultlab-crashes status
./install-user.sh --disable       # before switching to the system service
```

The user service is `faultlab-crashd.service` under `systemctl --user`.  It
cannot read root-only coredumps, pstore records or the rasdaemon database.  To
keep it running after logout or across reboots, enable linger once:
`loginctl enable-linger "$USER"`.

## pstore and kdump

`systemd-pstore` imports firmware panic records at boot.  The system collector
scans them and copies only the matching dmesg excerpt, not the raw archive.

The reference host reserves crash memory on the kernel command line, but kdump
is disabled in `/etc/default/kdump-tools` (`USE_KDUMP=0`).  To capture full
vmcores for kernel panics, enable it and load the crash kernel:

```bash
sudo sed -i 's/^#*USE_KDUMP=.*/USE_KDUMP=1/' /etc/default/kdump-tools
sudo kdump-config load
kdump-config show
```

New `/var/crash/*/vmcore` directories are detected on the next scan.  The
collector stores `vmcore-dmesg.txt` and the path; it does not copy the vmcore.
Inspect it with `sudo crash /usr/lib/debug/boot/vmlinux-$(uname -r) <vmcore>`.

## Retention and tuning

Defaults: keep 100 incidents, at most 2048 MiB, 15-second burst window,
5-minute dedup window.  Override in `/etc/faultlab/crashd.conf`:

```ini
FAULTLAB_CRASH_KEEP=100
FAULTLAB_CRASH_MAX_MB=2048
FAULTLAB_CRASH_BURST_SECONDS=15
FAULTLAB_CRASH_DEDUP_SECONDS=300
FAULTLAB_CRASH_COLLECT_ALL=0
FAULTLAB_CRASH_COPY_CORE=0
FAULTLAB_CRASH_MAX_CORE_MB=256
FAULTLAB_CRASH_SCAN_SECONDS=300
FAULTLAB_CRASH_PRUNE_SECONDS=86400
FAULTLAB_CRASH_QA=1
FAULTLAB_CRASH_QA_FEED=/var/log/faultlab/crashes.jsonl
```

`FAULTLAB_CRASH_COLLECT_ALL=1` stores coredumps from outside `faultlab.slice`
as `possible`.  `FAULTLAB_CRASH_COPY_CORE=1` copies the compressed core into
the incident folder (root only, size-limited); the default is a reference so
process memory is not duplicated.

## QA Sentinels feed

Each incident is also appended to a JSONL feed for QA Sentinels:

- system service: `/var/log/faultlab/crashes.jsonl`
- user service: `~/faultlab-crashes/qa.jsonl`

QA Sentinels consumes new lines with a byte cursor, inserts them into its
`crashes` table and stores the derived `component` label.  The feed carries the
process, signal/kind, allowed CPUs, fault-core verdict and a bounded context
block (trigger lines plus the coredump stack); it never carries the coredump
environment block or command line.

The feed is enabled by default.  Set `FAULTLAB_CRASH_QA=0` to disable it, or
`FAULTLAB_CRASH_QA_FEED=/path` to choose another file.  Existing incidents can
be emitted manually:

```bash
faultlab-crashes qa-feed --all --out /tmp/crashes.jsonl
sudo faultlab-crashes qa-feed --all --out /var/log/faultlab/crashes.jsonl
```

The system service backfills incidents created before the feed was enabled.

## Security

Coredump journal records can include `COREDUMP_ENVIRON` and
`COREDUMP_CMDLINE`, which may contain API keys, tokens and credentials.  The
collector never copies those fields.  `coredumpctl info` output has its command
line withheld.  Captured text also passes through a redaction filter for
credential-like assignments, token prefixes, private keys, URL userinfo, MAC
addresses, IP addresses and e-mail addresses.

Exports are written mode `0600` and can still contain process paths, user names
and crash data.  Keep them local and review before sharing.  A core file, if
copied, contains process memory and must be treated as sensitive evidence.

Existing systemd coredumps and journal entries created before this collector
may already contain `COREDUMP_ENVIRON` values.  The collector does not rewrite
or delete those records: restrict journal access and rotate any credential that
may have been captured there.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The suite covers CPU parsing, trigger classification, redaction, coredump field
whitelisting, attribution, incident creation, dedup, retention and checksums.
