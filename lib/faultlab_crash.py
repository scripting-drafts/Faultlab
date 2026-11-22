"""Shared crash-capture helpers for the fault-injection hatch.

The collector deliberately keeps only a small, named subset of journal
metadata.  Coredump journal records can contain COREDUMP_ENVIRON,
COREDUMP_CMDLINE and other fields with credentials; those fields are never
copied into an incident.
"""
from __future__ import annotations

import fcntl
import grp
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

SCHEMA = "faultlab.crash/1"
CONF_PATH = Path(os.environ.get("FAULTLAB_CONF", "/etc/faultlab/config"))
MODE_PATH = Path("/etc/faultlab/mode")
SYSTEM_CRASH_DIR = Path("/var/log/faultlab/crashes")
USER_CRASH_DIR = Path.home() / "faultlab-crashes"
SYS_CPU = Path("/sys/devices/system/cpu")

KIND_PRIORITY = {
    "event": 0,
    "warning": 1,
    "thermal": 1,
    "segfault": 2,
    "coredump": 3,
    "lockup": 3,
    "mce": 4,
    "oops": 4,
    "panic": 5,
}
SEVERITY_PRIORITY = {"info": 0, "warning": 1, "critical": 2}


# ---------------------------------------------------------------------------
# Small utilities


def utc_now() -> float:
    return time.time()


def iso(ts: float | None = None) -> str:
    value = utc_now() if ts is None else ts
    return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_text(path: str | os.PathLike[str], limit: int = 0) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit) if limit > 0 else fh.read()
    except OSError:
        return ""


def cpu_expand(value: str | None) -> list[int]:
    """Expand a kernel CPU list ("0-3,8") into sorted unique integers."""
    out: set[int] = set()
    for part in re.split(r"[\s,]+", (value or "").strip()):
        if not part:
            continue
        match = re.fullmatch(r"(\d+)-(\d+)", part)
        if match:
            first, last = int(match.group(1)), int(match.group(2))
            if first <= last:
                out.update(range(first, last + 1))
        elif part.isdigit():
            out.add(int(part))
    return sorted(out)


def cpu_text(cpus: Iterable[int]) -> str:
    values = sorted(set(cpus))
    if not values:
        return ""
    ranges: list[str] = []
    start = prev = values[0]
    for cpu in values[1:]:
        if cpu == prev + 1:
            prev = cpu
            continue
        ranges.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = cpu
    ranges.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(ranges)


def cpu_siblings(cpu: int) -> list[int]:
    own = SYS_CPU / f"cpu{cpu}" / "topology" / "thread_siblings_list"
    if own.exists():
        found = cpu_expand(read_text(own))
        if found:
            return found
    for path in SYS_CPU.glob("cpu[0-9]*/topology/thread_siblings_list"):
        found = cpu_expand(read_text(path))
        if cpu in found:
            return found
    return [cpu]


def cpu_online(cpu: int) -> bool:
    path = SYS_CPU / f"cpu{cpu}" / "online"
    return read_text(path).strip() != "0"


def cpus_online(cpus: Iterable[int]) -> bool:
    return all(cpu_online(cpu) for cpu in cpus)


def field_str(event: Mapping[str, Any], key: str, default: str = "") -> str:
    value = event.get(key, default)
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    if isinstance(value, list):
        try:
            return bytes(value).decode("utf-8", "replace")
        except (TypeError, ValueError):
            return default
    if isinstance(value, (int, float)):
        return str(value)
    return default


def run(
    argv: Sequence[str],
    timeout: float = 10.0,
    limit: int = 262144,
) -> tuple[int, str, str]:
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["SYSTEMD_COLORS"] = "0"
    try:
        proc = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout:g}s"
    except OSError as exc:
        return 127, "", f"{type(exc).__name__}: {exc}"
    out = proc.stdout or ""
    err = proc.stderr or ""
    if len(out) > limit:
        out = out[:limit] + "\n[output truncated]\n"
    if len(err) > 16384:
        err = err[:16384] + "\n[output truncated]\n"
    return proc.returncode, out, err


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Redaction


_SECRET_ASSIGN = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|API_?KEY|"
    r"ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH|COOKIE|SESSION)[A-Z0-9_]*)"
    r"(\s*[=:]\s*)([\"']?)([^\s\"',;]+)"
)
_SECRET_PREFIXES = re.compile(
    r"(?i)\b(?:sk-[a-z0-9_-]{12,}|ghp_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|"
    r"xox[baprs]-[a-z0-9-]{10,}|akia[0-9a-z]{16}|"
    r"aiza[0-9a-z_-]{20,})\b"
)
_BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.S,
)
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@]+@")
_MAC = re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.I)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(
    r"(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|"
    r"\b(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}\b"
)
_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@"
    r"(?!(?:[A-Za-z0-9-]+\.)*"
    r"(?:service|scope|slice|socket|target|mount|timer|path|device|"
    r"automount|swap)\b)"
    r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)


def redact(text: str) -> str:
    """Remove credentials and common network identifiers from captured text."""
    if not text:
        return ""
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    text = _PRIVATE_KEY.sub("<redacted-private-key>", text)
    text = _SECRET_ASSIGN.sub(r"\1\2\3<redacted>", text)
    text = _BEARER.sub(r"\1 <redacted>", text)
    text = _URL_USERINFO.sub(r"\1<redacted>@", text)
    text = _SECRET_PREFIXES.sub("<redacted-token>", text)
    text = _MAC.sub("<mac>", text)
    text = _IPV6.sub("<ip>", text)
    text = _IPV4.sub("<ip>", text)
    text = _EMAIL.sub("<email>", text)
    return text


# ---------------------------------------------------------------------------
# Classification


@dataclass(frozen=True)
class Trigger:
    kind: str
    severity: str
    reason: str


_CPU_RE = re.compile(r"\bCPU(?:#|:|\s)*(\d+)\b", re.I)
_RCU_CPU_RE = re.compile(r"\b(\d+)-\d*\.\.\.!")
_CONTINUATION = re.compile(
    r"(?i)^\s*(?:call trace|rip:|rsp:|rbp:|rax:|rbx:|rcx:|rdx:|rsi:|rdi:|"
    r"r08:|r09:|r10:|r11:|r12:|r13:|r14:|r15:|cr2:|code:|modules linked in|"
    r"hardware name|workqueue:|pkru:|kasan:|dump_stack|show_stack|cpu:|"
    r"comm:|tainted:|kernel panic|note:|\[ end trace)"
)
_LOCKUP_RE = re.compile(
    r"(?i)\b(?:soft lockup|hard lockup|watchdog:\s*bug|nmi watchdog|"
    r"rcu.*stall|hung task|blocked for more than)\b"
)
_OOPS_RE = re.compile(
    r"(?i)\b(?:oops|kernel bug at|bug:\s*(?:unable|kernel)|"
    r"general protection fault|invalid opcode|double fault|"
    r"unable to handle kernel)\b"
)
_MCE_RE = re.compile(
    r"(?i)\b(?:machine check|mce:|hardware error|uncorrected error|"
    r"corrected error|mca.*error)\b|\bedac\b.*\b(?:ce|ue|error|correct)"
)
# rasdaemon logs tracepoint management as "<subsys>:<event> event enabled"
# (and the reverse order).  These are control-plane messages, not hardware
# error records; treating the "mce:" prefix as an MCE creates false incidents.
_TRACEPOINT_CONTROL_RE = re.compile(
    r"(?i)^(?:rasdaemon(?:\[\d+\])?:\s*)?(?:"
    r"(?:enabled|disabled) event [a-z0-9_]+:[a-z0-9_]+|"
    r"[a-z0-9_]+:[a-z0-9_]+ event (?:enabled|disabled)"
    r")\s*$"
)
_PANIC_RE = re.compile(r"(?i)\b(?:kernel panic|panic occurred|end kernel panic)\b")
_WARNING_RE = re.compile(r"(?i)\bwarning:\s*(?:cpu|at)\b")
_SEGFAULT_RE = re.compile(r"(?i)\b(?:segfault at|traps:)\b")
_THERMAL_RE = re.compile(
    r"(?i)\b(?:thermal.*critical|critical temperature|throttl)"
)


def cpus_in_text(text: str) -> set[int]:
    found = {int(match.group(1)) for match in _CPU_RE.finditer(text)}
    found.update(int(match.group(1)) for match in _RCU_CPU_RE.finditer(text))
    return found


def classify_kernel_line(message: str) -> Trigger | None:
    text = (message or "").strip()
    if not text:
        return None
    low = text.lower()
    if "in-kernel mce decoding enabled" in low:
        return None
    if _TRACEPOINT_CONTROL_RE.match(text):
        return None
    if _PANIC_RE.search(text):
        return Trigger("panic", "critical", "kernel-panic")
    if _LOCKUP_RE.search(text):
        return Trigger("lockup", "critical", "lockup")
    if _OOPS_RE.search(text):
        return Trigger("oops", "critical", "oops")
    if _MCE_RE.search(text):
        severity = "critical" if re.search(
            r"(?i)uncorrect|uncorrected|fatal|panic", text
        ) else "warning"
        return Trigger("mce", severity, "hardware-error")
    if _WARNING_RE.search(text):
        return Trigger("warning", "warning", "kernel-warning")
    if _SEGFAULT_RE.search(text):
        return Trigger("segfault", "warning", "segfault")
    if _THERMAL_RE.search(text):
        return Trigger("thermal", "warning", "thermal")
    return None


def is_continuation(message: str) -> bool:
    return bool(_CONTINUATION.match((message or "").strip()))


def make_signature(kind: str, cpus: Iterable[int], message: str) -> str:
    text = redact(message or "").lower()
    text = re.sub(r"^\[[^\]]+\]\s*", "", text)
    text = re.sub(r"0x[0-9a-f]+", "0xX", text)
    text = re.sub(r"\b\d+(?:\.\d+)?\b", "N", text)
    text = re.sub(r"\s+", " ", text).strip()
    cpus_text = ",".join(str(cpu) for cpu in sorted(set(cpus)))
    return f"{kind}|{cpus_text}|{text[:180]}"


# ---------------------------------------------------------------------------
# Coredumps


_SIGNAL_NAMES = {int(sig): sig.name for sig in signal.Signals}


@dataclass
class CoredumpInfo:
    pid: int | None = None
    uid: int | None = None
    gid: int | None = None
    signal: int | None = None
    signal_name: str = ""
    comm: str = ""
    exe: str = ""
    cgroup: str = ""
    unit: str = ""
    slice: str = ""
    boot_id: str = ""
    timestamp_us: int = 0
    core_path: str = ""
    cpus_allowed: str = ""
    message: str = ""

    @classmethod
    def from_event(cls, event: Mapping[str, Any]) -> "CoredumpInfo":
        def as_int(key: str) -> int | None:
            raw = field_str(event, key)
            try:
                return int(raw)
            except (TypeError, ValueError):
                return None

        status = field_str(event, "COREDUMP_PROC_STATUS")
        allowed = ""
        match = re.search(r"^Cpus_allowed_list:\s*(\S+)", status, re.M)
        if match:
            allowed = match.group(1)
        signal_number = as_int("COREDUMP_SIGNAL")
        signal_name = field_str(event, "COREDUMP_SIGNAL_NAME")
        if not signal_name and signal_number in _SIGNAL_NAMES:
            signal_name = _SIGNAL_NAMES[signal_number]
        return cls(
            pid=as_int("COREDUMP_PID"),
            uid=as_int("COREDUMP_UID"),
            gid=as_int("COREDUMP_GID"),
            signal=signal_number,
            signal_name=signal_name,
            comm=field_str(event, "COREDUMP_COMM"),
            exe=field_str(event, "COREDUMP_EXE"),
            cgroup=field_str(event, "COREDUMP_CGROUP"),
            unit=field_str(event, "COREDUMP_UNIT"),
            slice=field_str(event, "COREDUMP_SLICE"),
            boot_id=field_str(event, "_BOOT_ID"),
            timestamp_us=as_int("COREDUMP_TIMESTAMP") or 0,
            core_path=field_str(event, "COREDUMP_FILENAME"),
            cpus_allowed=allowed,
            message=field_str(event, "MESSAGE"),
        )

    @property
    def is_faultlab(self) -> bool:
        return self.cgroup == "/faultlab.slice" or self.cgroup.startswith(
            "/faultlab.slice/"
        )

    def allowed_cpus(self) -> set[int]:
        return set(cpu_expand(self.cpus_allowed))

    def public_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "uid": self.uid,
            "gid": self.gid,
            "signal": self.signal,
            "signal_name": self.signal_name,
            "comm": self.comm,
            "exe": self.exe,
            "cgroup": self.cgroup,
            "unit": self.unit,
            "slice": self.slice,
            "boot_id": self.boot_id,
            "timestamp": iso(self.timestamp_us / 1_000_000)
            if self.timestamp_us
            else "",
            "cpus_allowed": self.cpus_allowed,
            "core_path": self.core_path,
        }


# ---------------------------------------------------------------------------
# Fault-core context


def _config_values(path: Path = CONF_PATH) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in read_text(path).splitlines():
        match = re.match(r"^([A-Z0-9_]+)=(.*)$", line.strip())
        if match:
            values[match.group(1)] = match.group(2).strip().strip("\"'")
    return values


@dataclass
class FaultContext:
    fault_cpu: int | None = None
    fault_cpus: tuple[int, ...] = ()
    control_cpus: tuple[int, ...] = ()
    safe_cpus: tuple[int, ...] = ()
    mode: str = "unknown"
    config_path: Path = CONF_PATH

    @classmethod
    def load(cls) -> "FaultContext":
        values = _config_values()
        env_fault = os.environ.get("FAULTLAB_FAULT_CPUS") or os.environ.get(
            "QA_FAULT_CORE_CPUS", ""
        )
        if env_fault:
            values["FAULT_CPUS"] = env_fault
        fault_cpu: int | None = None
        raw_seed = values.get("FAULT_CPU", "")
        if raw_seed.isdigit():
            fault_cpu = int(raw_seed)
        fault_cpus = tuple(cpu_expand(values.get("FAULT_CPUS", "")))
        if not fault_cpus and fault_cpu is not None:
            fault_cpus = tuple(cpu_siblings(fault_cpu))
        control = tuple(cpu_expand(values.get("CONTROL_CPUS", "")))
        safe = tuple(cpu_expand(values.get("SAFE_CPUS", "")))
        if not safe:
            possible = cpu_expand(read_text(SYS_CPU / "possible"))
            safe = tuple(cpu for cpu in possible if cpu not in fault_cpus)
        mode = read_text(MODE_PATH).strip() or "unknown"
        return cls(
            fault_cpu=fault_cpu,
            fault_cpus=fault_cpus,
            control_cpus=control,
            safe_cpus=safe,
            mode=mode,
            config_path=CONF_PATH,
        )

    @property
    def configured(self) -> bool:
        return bool(self.fault_cpus)

    def is_fault_cpu(self, cpu: int) -> bool:
        return cpu in self.fault_cpus

    def cpus_online(self) -> bool:
        return cpus_online(self.fault_cpus)

    def current_mode(self) -> str:
        return read_text(MODE_PATH).strip() or self.mode

    def label(self) -> str:
        cpus = cpu_text(self.fault_cpus)
        if not cpus:
            return "fault core (unconfigured)"
        online = [cpu for cpu in self.fault_cpus if cpu_online(cpu)]
        if online:
            core_id = read_text(
                SYS_CPU / f"cpu{online[0]}" / "topology" / "core_id"
            ).strip()
            if core_id:
                return f"physical core {core_id} (CPUs {cpus})"
        if self.fault_cpu is not None:
            return f"fault core (CPUs {cpus}; seed CPU {self.fault_cpu})"
        return f"fault core (CPUs {cpus})"

    def public_dict(self) -> dict[str, Any]:
        return {
            "fault_cpu": self.fault_cpu,
            "fault_cpus": list(self.fault_cpus),
            "control_cpus": list(self.control_cpus),
            "safe_cpus": list(self.safe_cpus),
            "mode": self.current_mode(),
            "label": self.label(),
            "config": str(self.config_path),
        }


# ---------------------------------------------------------------------------
# Incident storage


def _safe_relpath(name: str) -> Path:
    path = Path(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"unsafe incident file name: {name!r}")
    return path


def _fsync_write(path: Path, data: str | bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        with open(path, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(data if data.endswith("\n") else data + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    os.chmod(path, mode)


def _dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except OSError:
                pass
    return total


class IncidentStore:
    def __init__(self, root: Path, system: bool | None = None) -> None:
        self.root = Path(root)
        self.system = (
            os.geteuid() == 0 if system is None else bool(system)
        )
        self.index = self.root / "index.jsonl"
        self.pruned = self.root / "pruned.jsonl"
        self.state_dir = self.root / "state"
        self.exports = self.root / "exports"
        self.latest = self.root / "latest"

    # -- permissions ------------------------------------------------------
    @property
    def dir_mode(self) -> int:
        return 0o750 if self.system else 0o700

    @property
    def file_mode(self) -> int:
        return 0o640 if self.system else 0o600

    def _adm_gid(self) -> int | None:
        try:
            return grp.getgrnam("adm").gr_gid
        except KeyError:
            return None

    def _owner(self, path: Path, directory: bool = False) -> None:
        if path.is_symlink():
            return
        try:
            os.chmod(path, self.dir_mode if directory else self.file_mode)
            if self.system:
                gid = self._adm_gid()
                os.chown(path, 0, gid if gid is not None else 0)
        except OSError:
            pass

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self._owner(self.root, directory=True)
        for path in (self.state_dir, self.exports):
            path.mkdir(parents=True, exist_ok=True)
            self._owner(path, directory=True)
        if not self.index.exists():
            _fsync_write(self.index, "", self.file_mode)
            self._owner(self.index)
        readme = self.root / "README.txt"
        if not readme.exists():
            _fsync_write(readme, render_store_readme(self.system), self.file_mode)
            self._owner(readme)

    # -- locking and index ------------------------------------------------
    def _append_locked(self, path: Path, payload: Mapping[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a+", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            fh.write(json.dumps(payload, sort_keys=True, separators=(",", ":")))
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        self._owner(path)

    def read_index(self) -> list[dict[str, Any]]:
        latest: dict[str, dict[str, Any]] = {}
        if self.index.exists():
            for line in read_text(self.index).splitlines():
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(row, dict) or not row.get("id"):
                    continue
                latest[str(row["id"])] = row
        rows = []
        for row in latest.values():
            directory = self.root / str(row.get("dir", row["id"]))
            if directory.is_dir():
                rows.append(row)
        known = {str(row.get("dir", row["id"])) for row in rows}
        for directory in self.incident_dirs():
            if directory.name in known:
                continue
            try:
                incident = json.loads(
                    read_text(directory / "incident.json")
                )
            except ValueError:
                continue
            if not isinstance(incident, dict):
                continue
            rows.append(
                {
                    "id": incident.get("id", directory.name),
                    "dir": directory.name,
                    "created": incident.get("created", ""),
                    "created_ts": incident.get("created_ts", 0),
                    "last_seen": incident.get("last_seen", ""),
                    "last_seen_ts": incident.get("last_seen_ts", 0),
                    "kind": incident.get("kind", ""),
                    "severity": incident.get("severity", ""),
                    "attribution": incident.get("attribution", ""),
                    "signature": incident.get("signature", ""),
                    "boot_id": incident.get("boot_id", ""),
                    "pid": incident.get("pid"),
                    "comm": incident.get("comm", ""),
                    "exe": incident.get("exe", ""),
                    "cgroup": incident.get("cgroup", ""),
                    "matched_cpus": incident.get("matched_cpus", []),
                    "event_cpus": incident.get("event_cpus", []),
                    "occurrences": incident.get("occurrences", 1),
                    "size": incident.get("size", 0),
                }
            )
        def last_seen(row: Mapping[str, Any]) -> float:
            try:
                return float(row.get("last_seen_ts", 0))
            except (TypeError, ValueError):
                return 0.0

        rows.sort(key=last_seen, reverse=True)
        return rows

    def recent(
        self, boot_id: str, signature: str, window: float
    ) -> dict[str, Any] | None:
        now = utc_now()
        for row in self.read_index():
            if row.get("boot_id") != boot_id or row.get("signature") != signature:
                continue
            try:
                last_seen = float(row.get("last_seen_ts", 0))
            except (TypeError, ValueError):
                continue
            if now - last_seen <= window:
                return row
        return None

    # -- create / update --------------------------------------------------
    def _write_payload(
        self, tmp: Path, files: Mapping[str, str | bytes]
    ) -> dict[str, dict[str, Any]]:
        written: dict[str, dict[str, Any]] = {}
        for name, content in files.items():
            rel = _safe_relpath(name)
            target = tmp / rel
            is_binary = isinstance(content, bytes)
            if not is_binary:
                content = redact(content)
            _fsync_write(target, content, 0o600 if is_binary else self.file_mode)
            self._owner(target)
            written[str(rel)] = {
                "size": target.stat().st_size,
                "sha256": sha256_file(target),
            }
        return written

    def _checksums(self, directory: Path) -> None:
        lines = []
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.name == "checksums.sha256":
                continue
            rel = path.relative_to(directory).as_posix()
            lines.append(f"{sha256_file(path)}  {rel}")
        _fsync_write(directory / "checksums.sha256", "\n".join(lines), self.file_mode)
        self._owner(directory / "checksums.sha256")

    def create(self, record: dict[str, Any], files: Mapping[str, str | bytes]) -> Path:
        self.ensure()
        incident_id = str(record["id"])
        final = self.root / incident_id
        if final.exists():
            incident_id = f"{incident_id}-{os.getpid()}"
            final = self.root / incident_id
        tmp = self.root / f".tmp-{incident_id}"
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(mode=self.dir_mode)
        self._owner(tmp, directory=True)
        try:
            record = dict(record)
            record.setdefault("store", "system" if self.system else "user")
            record["id"] = incident_id
            record["dir"] = incident_id
            payload = dict(files)
            payload["README.txt"] = render_readme(record)
            written = self._write_payload(tmp, payload)
            record["files"] = written
            record["size"] = sum(item["size"] for item in written.values())
            _fsync_write(
                tmp / "incident.json",
                json.dumps(record, indent=2, sort_keys=True),
                self.file_mode,
            )
            self._owner(tmp / "incident.json")
            self._checksums(tmp)
            for path in tmp.iterdir():
                self._owner(path, directory=path.is_dir())
            tmp.rename(final)
            self._fsync_dir(self.root)
            self._append_locked(
                self.index,
                {
                    "id": incident_id,
                    "dir": incident_id,
                    "created": record.get("created", ""),
                    "created_ts": record.get("created_ts", 0),
                    "last_seen": record.get("last_seen", ""),
                    "last_seen_ts": record.get("last_seen_ts", 0),
                    "kind": record.get("kind", ""),
                    "severity": record.get("severity", ""),
                    "attribution": record.get("attribution", ""),
                    "signature": record.get("signature", ""),
                    "boot_id": record.get("boot_id", ""),
                    "pid": record.get("pid"),
                    "comm": record.get("comm", ""),
                    "exe": record.get("exe", ""),
                    "cgroup": record.get("cgroup", ""),
                    "matched_cpus": record.get("matched_cpus", []),
                    "event_cpus": record.get("event_cpus", []),
                    "occurrences": record.get("occurrences", 1),
                    "size": record.get("size", 0),
                },
            )
            self._set_latest(incident_id)
        except Exception:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        return final

    def update(
        self,
        incident_id: str,
        record: dict[str, Any],
        extra_files: Mapping[str, str | bytes] | None = None,
    ) -> Path:
        directory = self.root / incident_id
        if not directory.is_dir():
            raise FileNotFoundError(directory)
        if extra_files:
            self._write_payload(directory, extra_files)
        record = dict(record)
        record.setdefault("store", "system" if self.system else "user")
        record["id"] = incident_id
        record["dir"] = incident_id
        record["files"] = {
            str(path.relative_to(directory)): {
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in sorted(directory.rglob("*"))
            if path.is_file()
            and path.name not in ("incident.json", "README.txt", "checksums.sha256")
        }
        record["size"] = sum(item["size"] for item in record["files"].values())
        _fsync_write(
            directory / "README.txt", render_readme(record), self.file_mode
        )
        self._owner(directory / "README.txt")
        _fsync_write(
            directory / "incident.json",
            json.dumps(record, indent=2, sort_keys=True),
            self.file_mode,
        )
        self._owner(directory / "incident.json")
        self._checksums(directory)
        self._append_locked(
            self.index,
            {
                "id": incident_id,
                "dir": incident_id,
                "created": record.get("created", ""),
                "created_ts": record.get("created_ts", 0),
                "last_seen": record.get("last_seen", ""),
                "last_seen_ts": record.get("last_seen_ts", 0),
                "kind": record.get("kind", ""),
                "severity": record.get("severity", ""),
                "attribution": record.get("attribution", ""),
                "signature": record.get("signature", ""),
                "boot_id": record.get("boot_id", ""),
                "pid": record.get("pid"),
                "comm": record.get("comm", ""),
                "exe": record.get("exe", ""),
                "cgroup": record.get("cgroup", ""),
                "matched_cpus": record.get("matched_cpus", []),
                "event_cpus": record.get("event_cpus", []),
                "occurrences": record.get("occurrences", 1),
                "size": record.get("size", 0),
            },
        )
        self._set_latest(incident_id)
        return directory

    def append_occurrence(
        self, incident_id: str, payload: Mapping[str, Any]
    ) -> None:
        directory = self.root / incident_id
        if not directory.is_dir():
            raise FileNotFoundError(directory)
        self._append_locked(directory / "occurrences.jsonl", payload)

    def _fsync_dir(self, path: Path) -> None:
        try:
            fd = os.open(path, os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            pass

    def _set_latest(self, incident_id: str) -> None:
        tmp = self.root / ".latest.tmp"
        try:
            if tmp.is_symlink() or tmp.exists():
                tmp.unlink()
            os.symlink(incident_id, tmp)
            os.replace(tmp, self.latest)
        except OSError:
            pass

    # -- retention --------------------------------------------------------
    def incident_dirs(self) -> list[Path]:
        if not self.root.is_dir():
            return []
        skip = {self.state_dir.name, self.exports.name}
        found = []
        for entry in self.root.iterdir():
            if entry.is_symlink() or not entry.is_dir():
                continue
            if entry.name.startswith(".") or entry.name in skip:
                continue
            if (entry / "incident.json").is_file():
                found.append(entry)
        return found

    def prune(
        self, keep: int, max_mb: int, dry_run: bool = False
    ) -> list[Path]:
        def mtime(path: Path) -> float:
            try:
                return (path / "incident.json").stat().st_mtime
            except OSError:
                return 0.0

        directories = self.incident_dirs()
        directories.sort(key=mtime, reverse=True)
        remove: list[Path] = []
        for directory in directories[max(0, keep):]:
            remove.append(directory)
        kept = [directory for directory in directories if directory not in remove]
        total = sum(_dir_size(directory) for directory in kept)
        limit = max(0, max_mb) * 1024 * 1024
        for directory in reversed(kept):
            if total <= limit:
                break
            total -= _dir_size(directory)
            remove.append(directory)
        if dry_run:
            return remove
        for directory in remove:
            size = _dir_size(directory)
            shutil.rmtree(directory, ignore_errors=True)
            self._append_locked(
                self.pruned,
                {
                    "id": directory.name,
                    "ts": iso(),
                    "reason": "retention",
                    "bytes": size,
                },
            )
        return remove

    # -- checks -----------------------------------------------------------
    def verify(self, incident_id: str) -> list[str]:
        directory = self.root / incident_id
        checksum_file = directory / "checksums.sha256"
        problems: list[str] = []
        if not checksum_file.is_file():
            return [f"missing {checksum_file.name}"]
        for line in read_text(checksum_file).splitlines():
            parts = line.split("  ", 1)
            if len(parts) != 2:
                continue
            expected, name = parts
            path = directory / name
            if not path.is_file():
                problems.append(f"missing {name}")
                continue
            if sha256_file(path) != expected:
                problems.append(f"checksum mismatch: {name}")
        return problems

    def resolve(self, ref: str) -> Path:
        if "/" in ref or "\\" in ref or ref in (".", ".."):
            raise ValueError(f"invalid incident reference: {ref}")
        if ref in ("latest", "@latest"):
            if self.latest.is_symlink():
                target = self.root / os.readlink(self.latest)
                if (target / "incident.json").is_file():
                    return target
            rows = self.read_index()
            if rows:
                return self.root / str(rows[0]["dir"])
            raise FileNotFoundError("no incidents")
        exact = self.root / ref
        if (exact / "incident.json").is_file():
            return exact
        matches = [
            path
            for path in self.incident_dirs()
            if path.name.startswith(ref)
        ]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise FileNotFoundError(ref)
        raise ValueError(f"ambiguous incident reference: {ref}")

    # -- state ------------------------------------------------------------
    def state_path(self, name: str) -> Path:
        return self.state_dir / name

    def load_state(self, name: str, default: Any) -> Any:
        path = self.state_path(name)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return default

    def save_state(self, name: str, value: Any) -> None:
        path = self.state_path(name)
        _fsync_write(path, json.dumps(value, sort_keys=True), self.file_mode)
        self._owner(path)

    def heartbeat(self, extra: Mapping[str, Any]) -> None:
        self.save_state(
            "heartbeat.json",
            {"ts": utc_now(), "iso": iso(), "pid": os.getpid(), **extra},
        )


def _attribution_text(value: str) -> str:
    return {
        "direct": "Kernel evidence names a fault-core CPU.",
        "possible": "No CPU was named; a fault-core contribution cannot be excluded.",
        "other-cpu": "A machine-check event named another CPU; kept for package comparison.",
        "none": "Context only; no fault-core attribution.",
    }.get(value, value)


def render_store_readme(system: bool) -> str:
    prefix = "sudo " if system else ""
    return f"""Faultlab crash store
====================

One folder per incident.  Each folder has a README.txt, incident.json,
kernel context, RAS/topology snapshots and checksums.

  {prefix}faultlab-crashes status
  {prefix}faultlab-crashes list
  {prefix}faultlab-crashes show latest
  {prefix}faultlab-crashes verify latest
  {prefix}faultlab-crashes export latest --out /root/crash.tar.gz
  {prefix}faultlab-crashes prune --keep 100 --max-mb 2048 --dry-run

index.jsonl is the append-only index; latest points at the newest incident.
The collector redacts credentials and does not copy coredump environment
blocks or command lines.  Core files are referenced, not copied, unless
FAULTLAB_CRASH_COPY_CORE=1.  Treat exports and any copied core as sensitive.
"""


def render_readme(record: Mapping[str, Any]) -> str:
    faultlab = record.get("faultlab") or {}
    coredump = record.get("coredump") or {}
    prefix = "sudo " if record.get("store") == "system" else ""
    core_prefix = "sudo " if record.get("store") != "user" else ""
    lines = [
        "Faultlab crash incident",
        "=======================",
        "",
        f"ID:           {record.get('id', '')}",
        f"Kind:         {record.get('kind', '')} ({record.get('severity', '')})",
        f"Attribution:  {record.get('attribution', '')} - "
        f"{_attribution_text(str(record.get('attribution', '')))}",
        f"First seen:   {record.get('created', '')}",
        f"Last seen:    {record.get('last_seen', '')}",
        f"Occurrences:  {record.get('occurrences', 1)}",
        f"Source:       {record.get('source', '')}",
        f"Fault core:   {faultlab.get('label', 'unknown')}",
        f"Mode:         {faultlab.get('mode', 'unknown')}",
        f"Boot ID:      {record.get('boot_id', '')}",
    ]
    if record.get("matched_cpus"):
        lines.append(f"Matched CPUs: {record.get('matched_cpus')}")
    if record.get("event_cpus"):
        lines.append(f"All CPUs:     {record.get('event_cpus')}")
    if record.get("pid") or coredump:
        lines.extend(
            [
                "",
                "Process",
                "-------",
                f"PID:          {record.get('pid') or coredump.get('pid')}",
                f"Command:      {record.get('comm') or coredump.get('comm', '')}",
            ]
        )
        executable = record.get("exe") or coredump.get("exe", "")
        if executable:
            lines.append(f"Executable:   {executable}")
        if coredump:
            lines.extend(
                [
                    f"Signal:       {coredump.get('signal_name', '')} "
                    f"({coredump.get('signal', '')})",
                    f"CPUs allowed: {coredump.get('cpus_allowed', '')}",
                ]
            )
        cgroup = record.get("cgroup") or coredump.get("cgroup", "")
        if cgroup:
            lines.append(f"Cgroup:       {cgroup}")
    lines.extend(["", "Trigger", "-------"])
    for item in (record.get("trigger_lines") or [])[:12]:
        message = str(item.get("message", "")).replace("\n", " ")
        lines.append(f"{item.get('ts', '')}  {message[:220]}")
    if not record.get("trigger_lines"):
        lines.append("(no trigger lines captured)")
    lines.extend(
        [
            "",
            "Files",
            "-----",
            "journal.txt       kernel context around the event",
            "dmesg.txt         kernel ring buffer at capture time",
            "ras.txt           ras-mc-ctl summary/errors (system mode)",
            "topology.txt      CPU topology, isolation and online state",
            "processes.txt     tasks sampled on fault-core CPUs",
            "sensors.txt       temperatures at capture time",
            "occurrences.jsonl repeated events merged into this folder",
            "coredump/         coredump metadata and backtrace (no env/cmdline)",
            "checksums.sha256  SHA-256 of every file in this folder",
            "",
            "Inspect",
            "-------",
            f"{prefix}faultlab-crashes show {record.get('id', '')}",
            f"{prefix}faultlab-crashes export {record.get('id', '')}",
        ]
    )
    if coredump.get("pid"):
        lines.append(f"{core_prefix}coredumpctl info {coredump.get('pid')}")
        lines.append(f"{core_prefix}coredumpctl gdb {coredump.get('pid')}")
    lines.extend(
        [
            "",
            "Security",
            "--------",
            "Environment blocks, command lines and credential-like strings are",
            "not stored.  Core files are referenced, not copied, by default; a",
            "core contains process memory and may still hold secrets.",
            "",
        ]
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Capture helpers


def capture_topology(ctx: FaultContext) -> str:
    lines = [f"captured: {iso()}", f"fault core: {ctx.label()}"]
    lines.append(f"mode: {ctx.mode}")
    lines.append(f"fault cpus: {cpu_text(ctx.fault_cpus)}")
    lines.append(f"control cpus: {cpu_text(ctx.control_cpus)}")
    lines.append(f"safe cpus: {cpu_text(ctx.safe_cpus)}")
    lines.append("")
    rc, out, err = run(
        ["lscpu", "-e=CPU,CORE,SOCKET,NODE,ONLINE,MAXMHZ,MINMHZ"], timeout=10
    )
    lines.append("lscpu:")
    lines.append(out.strip() or err.strip() or "(unavailable)")
    lines.append("")
    for cpu in ctx.fault_cpus:
        online = read_text(SYS_CPU / f"cpu{cpu}" / "online").strip()
        siblings = read_text(
            SYS_CPU / f"cpu{cpu}" / "topology" / "thread_siblings_list"
        ).strip()
        core_id = read_text(
            SYS_CPU / f"cpu{cpu}" / "topology" / "core_id"
        ).strip()
        lines.append(
            f"cpu{cpu}: online={online or '1'} siblings={siblings or '?'} "
            f"core_id={core_id or '?'}"
        )
    lines.append("")
    for name in ("isolated", "nohz_full", "possible", "online"):
        lines.append(f"{name}: {read_text(SYS_CPU / name).strip()}")
    lines.append(f"cmdline: {read_text('/proc/cmdline').strip()}")
    rc, out, err = run(
        ["systemctl", "show", "faultlab.slice", "-p", "AllowedCPUs"], timeout=5
    )
    if out.strip():
        lines.append(f"faultlab.slice: {out.strip()}")
    mode_cmd = shutil.which("faultlab-mode") or "/usr/local/sbin/faultlab-mode"
    if os.access(mode_cmd, os.X_OK):
        rc, out, err = run([mode_cmd, "status"], timeout=10)
        if out.strip() or err.strip():
            lines.extend(
                ["", "faultlab-mode status:", out.strip() or err.strip()]
            )
    return "\n".join(lines) + "\n"


def capture_dmesg() -> str:
    rc, out, err = run(["dmesg", "-T"], timeout=15)
    if rc == 0 and out.strip():
        return redact(out)
    rc, out, err = run(
        ["journalctl", "-k", "-b", "0", "-n", "500", "-o", "short-iso"],
        timeout=20,
    )
    if out.strip():
        return redact(out)
    return redact("(dmesg unavailable: " + (err.strip() or f"rc={rc}") + ")\n")


def capture_ras(system: bool) -> str:
    if not system:
        return "ras-mc-ctl requires root; skipped in user mode.\n"
    parts = [f"captured: {iso()}"]
    for args in (["--summary"], ["--errors"]):
        rc, out, err = run(["ras-mc-ctl", *args], timeout=25)
        parts.append(f"\n$ ras-mc-ctl {' '.join(args)} (rc={rc})")
        if out.strip():
            parts.append(redact(out.strip()))
        if err.strip():
            parts.append(redact(err.strip()))
    return "\n".join(parts) + "\n"


def capture_processes(ctx: FaultContext) -> str:
    rc, out, err = run(
        ["ps", "-eLo", "pid,tid,psr,comm", "--no-headers"], timeout=10
    )
    if rc != 0:
        return redact(f"ps failed: {err.strip()}\n")
    wanted = set(ctx.fault_cpus)
    rows = [
        line
        for line in out.splitlines()
        if line.split() and line.split()[2].isdigit()
        and int(line.split()[2]) in wanted
    ]
    if not rows:
        return "No tasks sampled on fault-core CPUs.\n"
    header = "PID TID CPU COMMAND"
    return header + "\n" + "\n".join(rows) + "\n"


def capture_sensors() -> str:
    rc, out, err = run(["sensors"], timeout=8)
    if rc == 0 and out.strip():
        return redact(out)
    return "(sensors unavailable)\n"


_COREDUMP_FIELDS = (
    "PID",
    "UID",
    "GID",
    "Signal",
    "Timestamp",
    "Executable",
    "Control Group",
    "Unit",
    "User Unit",
    "Slice",
    "Owner UID",
    "Boot ID",
    "Machine ID",
    "Hostname",
    "Storage",
    "Size on Disk",
    "Message",
)
_FIELD_RE = re.compile(
    r"^\s*(?:" + "|".join(re.escape(item) for item in _COREDUMP_FIELDS) + r"):"
)


def filter_coredump_info(text: str) -> str:
    """Drop the command line (which may contain secrets) from coredumpctl."""
    output: list[str] = []
    skipping = False
    for line in text.splitlines():
        if re.match(r"^\s*Command Line:", line):
            output.append(" Command Line: (withheld; may contain credentials)")
            skipping = True
            continue
        if skipping:
            if _FIELD_RE.match(line):
                skipping = False
            else:
                continue
        output.append(line)
    return "\n".join(output) + ("\n" if output else "")


def capture_coredump(
    ctx: FaultContext, info: CoredumpInfo, system: bool
) -> dict[str, str | bytes]:
    files: dict[str, str | bytes] = {}
    pid = info.pid
    if pid is None:
        return files
    rc, out, err = run(
        ["coredumpctl", "info", str(pid), "--no-pager"], timeout=45
    )
    if rc == 0 and out.strip():
        files["coredump/info.txt"] = redact(filter_coredump_info(out))
    else:
        files["coredump/info.txt"] = redact(
            f"coredumpctl info failed (rc={rc}): {err.strip()}\n"
        )
    if info.message.strip():
        files["coredump/backtrace.txt"] = redact(info.message)
    readme = [
        "Coredump metadata",
        "=================",
        f"pid: {pid}",
        f"executable: {info.exe}",
        f"signal: {info.signal_name} ({info.signal})",
        f"cgroup: {info.cgroup}",
        f"core path: {info.core_path or '(not recorded)'}",
        f"cpus allowed: {info.cpus_allowed or '(unknown)'}",
        "",
        "The core file is not copied by default.  Process memory can contain",
        "credentials.  Inspect it in place, as root:",
        f"  sudo coredumpctl info {pid}",
        f"  sudo coredumpctl gdb {pid}",
        "",
    ]
    files["coredump/README.txt"] = "\n".join(readme)
    if (
        system
        and os.environ.get("FAULTLAB_CRASH_COPY_CORE", "0") == "1"
        and info.core_path
    ):
        source = Path(info.core_path)
        if not str(source).startswith("/var/lib/systemd/coredump/"):
            return files
        try:
            size = source.stat().st_size
            try:
                max_core_mb = int(
                    os.environ.get("FAULTLAB_CRASH_MAX_CORE_MB", "256")
                )
            except ValueError:
                max_core_mb = 256
            limit = max(0, max_core_mb) * 1024 * 1024
            if 0 < size <= limit:
                files["coredump/core.zst"] = source.read_bytes()
        except OSError:
            pass
    return files


def capture_journal_context(
    boot_id: str, start: float, end: float
) -> str:
    args = [
        "journalctl",
        "-k",
        "-o",
        "short-iso",
        "--no-pager",
        "-n",
        "400",
        "--since",
        f"@{max(0, int(start) - 20)}",
        "--until",
        f"@{int(end) + 5}",
    ]
    if boot_id and not boot_id.startswith(("pstore:", "kdump:")):
        args[1:1] = ["-b", boot_id]
    rc, out, err = run(args, timeout=25, limit=524288)
    if out.strip():
        return redact(out)
    return redact(f"(journal context unavailable: {err.strip() or f'rc={rc}'})\n")


# ---------------------------------------------------------------------------
# Bursts and incident decisions


@dataclass
class Burst:
    boot_id: str
    first_ts: float
    last_ts: float
    source: str = "kernel"
    kind: str = "event"
    severity: str = "info"
    trigger: str = ""
    signature: str = ""
    matched_cpus: set[int] = field(default_factory=set)
    event_cpus: set[int] = field(default_factory=set)
    text_cpus: set[int] = field(default_factory=set)
    lines: list[dict[str, Any]] = field(default_factory=list)
    coredump: CoredumpInfo | None = None
    pid: int | None = None
    comm: str = ""
    cgroup: str = ""
    unit: str = ""

    def _append(
        self,
        message: str,
        ts: float,
        pid: int | None,
        comm: str,
        cgroup: str,
        unit: str,
        trigger: bool = False,
    ) -> None:
        clean = redact(message).strip()
        if not clean:
            return
        self.lines.append(
            {
                "ts": iso(ts),
                "message": clean[:4000],
                "pid": pid,
                "comm": comm,
                "cgroup": cgroup,
                "unit": unit,
                "trigger": trigger,
            }
        )
        if len(self.lines) > 300:
            del self.lines[:-300]
        if trigger or is_continuation(clean):
            self.last_ts = max(self.last_ts, ts)

    def add_trigger(
        self,
        trigger: Trigger,
        message: str,
        ts: float,
        pid: int | None,
        comm: str,
        cgroup: str,
        unit: str,
        cpus: set[int],
    ) -> None:
        self.event_cpus.update(cpus)
        self.text_cpus.update(cpus)
        if self.pid is None:
            self.pid = pid
        if not self.comm:
            self.comm = comm
        if not self.cgroup:
            self.cgroup = cgroup
        if not self.unit:
            self.unit = unit
        if KIND_PRIORITY.get(trigger.kind, 0) > KIND_PRIORITY.get(self.kind, 0):
            self.kind = trigger.kind
            self.trigger = trigger.reason
        if SEVERITY_PRIORITY.get(trigger.severity, 0) > SEVERITY_PRIORITY.get(
            self.severity, 0
        ):
            self.severity = trigger.severity
        self.signature = make_signature(trigger.kind, cpus, message)
        self._append(message, ts, pid, comm, cgroup, unit, trigger=True)

    def add_coredump(self, info: CoredumpInfo) -> None:
        self.coredump = info
        self.pid = info.pid
        self.comm = info.comm
        self.cgroup = info.cgroup
        self.unit = info.unit
        self.event_cpus.update(info.allowed_cpus())
        if self.kind == "event":
            self.kind = "coredump"
            self.severity = "critical"
            self.trigger = "coredump"
        self.signature = make_signature(
            "coredump",
            info.allowed_cpus(),
            f"{info.exe} {info.comm} {info.signal_name}",
        )
        self.last_ts = max(self.last_ts, info.timestamp_us / 1_000_000)

    def add_context(
        self,
        message: str,
        ts: float,
        pid: int | None,
        comm: str,
        cgroup: str,
        unit: str,
    ) -> None:
        self._append(message, ts, pid, comm, cgroup, unit)

    def attribution(self, ctx: FaultContext, collect_all: bool) -> str:
        self.matched_cpus = self.text_cpus & set(ctx.fault_cpus)
        if self.matched_cpus:
            return "direct"
        if self.coredump:
            if self.coredump.is_faultlab:
                return "direct"
            if ctx.cpus_online() and self.coredump.allowed_cpus() & set(
                ctx.fault_cpus
            ):
                return "possible"
        if self.kind == "mce" and self.event_cpus:
            return "other-cpu"
        if self.kind in ("mce", "panic"):
            return "possible"
        if ctx.current_mode() == "lab" and self.kind in ("oops", "lockup"):
            return "possible"
        if collect_all:
            return "possible"
        return "none"

    def should_store(self, attribution: str, collect_all: bool) -> bool:
        if attribution in ("direct", "possible", "other-cpu"):
            return True
        return collect_all

    def record(
        self, ctx: FaultContext, attribution: str, now: float | None = None
    ) -> dict[str, Any]:
        self.matched_cpus = self.text_cpus & set(ctx.fault_cpus)
        created = iso(self.first_ts)
        digest = hashlib.sha256(self.signature.encode("utf-8")).hexdigest()[:8]
        stamp = datetime.fromtimestamp(
            self.first_ts, timezone.utc
        ).strftime("%Y%m%dT%H%M%SZ")
        incident_id = f"{stamp}-{self.kind}-{digest}"
        triggers = [line for line in self.lines if line.get("trigger")][:12]
        if not triggers:
            triggers = self.lines[:6]
        coredump = self.coredump.public_dict() if self.coredump else {}
        return {
            "schema": SCHEMA,
            "id": incident_id,
            "created": created,
            "created_ts": self.first_ts,
            "last_seen": iso(self.last_ts),
            "last_seen_ts": self.last_ts,
            "occurrences": 1,
            "boot_id": self.boot_id,
            "source": self.source,
            "kind": self.kind,
            "severity": self.severity,
            "attribution": attribution,
            "signature": self.signature,
            "trigger": self.trigger,
            "matched_cpus": sorted(self.matched_cpus),
            "event_cpus": sorted(self.event_cpus),
            "pid": self.pid,
            "comm": self.comm,
            "exe": coredump.get("exe", ""),
            "cgroup": self.cgroup,
            "unit": self.unit,
            "trigger_lines": triggers,
            "coredump": coredump,
            "faultlab": ctx.public_dict(),
            "redaction": "credentials, environment blocks and command lines withheld",
            "host": {
                "hostname": os.uname().nodename,
                "kernel": os.uname().release,
                "boot_id": read_text("/proc/sys/kernel/random/boot_id").strip(),
                "microcode": _microcode(),
            },
        }


def _microcode() -> str:
    for line in read_text("/proc/cpuinfo").splitlines():
        if line.lower().startswith("microcode"):
            return line.split(":", 1)[-1].strip()
    return ""


# ---------------------------------------------------------------------------
# QA Sentinels feed


QA_FEED_SCHEMA = "faultlab.crash.qa/1"
_KERNEL_KINDS = ("mce", "oops", "panic", "lockup", "warning", "thermal")


def qa_feed_path(store: IncidentStore, system: bool) -> Path:
    override = os.environ.get("FAULTLAB_CRASH_QA_FEED")
    if override:
        return Path(override)
    if system:
        return Path("/var/log/faultlab/crashes.jsonl")
    return store.root / "qa.jsonl"


def _feed_component(record: Mapping[str, Any]) -> str:
    coredump = record.get("coredump") or {}
    comm = str(record.get("comm") or coredump.get("comm") or "").strip()
    exe = str(record.get("exe") or coredump.get("exe") or "").strip()
    if comm:
        return comm
    if exe:
        return Path(exe).name
    if str(record.get("kind") or "") in _KERNEL_KINDS:
        return "kernel"
    return "unknown"


def _feed_context(record: Mapping[str, Any], incident_dir: Path) -> str:
    faultlab = record.get("faultlab") or {}
    coredump = record.get("coredump") or {}
    configured = str(faultlab.get("label") or "unconfigured")
    if record.get("matched_cpus") or record.get("attribution") == "direct":
        fault_core = configured
    else:
        fault_core = f"unattributed (no CPU evidence; configured: {configured})"
    lines = [
        f"incident={record.get('id', '')}",
        f"kind={record.get('kind', '')} severity={record.get('severity', '')}",
        f"attribution={record.get('attribution', '')} "
        f"source={record.get('source', '')}",
        f"fault_core={fault_core} mode={faultlab.get('mode', '')}",
        f"cgroup={record.get('cgroup', '')}",
        f"matched_cpus={record.get('matched_cpus', [])} "
        f"event_cpus={record.get('event_cpus', [])}",
        f"occurrences={record.get('occurrences', 1)}",
    ]
    for item in (record.get("trigger_lines") or [])[:12]:
        message = str(item.get("message") or "").replace("\n", " ")
        lines.append(f"{item.get('ts', '')} {message[:500]}")
    if coredump:
        lines.append(
            f"coredump pid={coredump.get('pid')} "
            f"signal={coredump.get('signal_name')} "
            f"exe={coredump.get('exe', '')} "
            f"cgroup={coredump.get('cgroup', '')}"
        )
        for name in ("coredump/backtrace.txt", "coredump/info.txt"):
            text = read_text(incident_dir / name, limit=12000)
            if text.strip():
                lines.append(f"--- {name} ---")
                lines.append(text.strip())
    return "\n".join(lines)[:24000]


def qa_feed_record(
    record: Mapping[str, Any], incident_dir: Path
) -> dict[str, Any]:
    """Build one stable JSONL row for QA Sentinels."""
    coredump = record.get("coredump") or {}
    attribution = str(record.get("attribution") or "none")
    involved = {
        "direct": 1,
        "other-cpu": 0,
        "possible": None,
        "none": 0,
    }.get(attribution, None)
    cpus = (
        str(coredump.get("cpus_allowed") or "")
        or cpu_text(record.get("event_cpus") or [])
    )
    component = _feed_component(record)
    return {
        "schema": QA_FEED_SCHEMA,
        "id": str(record.get("id") or incident_dir.name),
        "fingerprint": f"crash-feed|{record.get('id') or incident_dir.name}",
        "ts": record.get("created") or iso(),
        "last_ts": record.get("last_seen") or record.get("created") or iso(),
        "occurrences": int(record.get("occurrences", 1) or 1),
        "kind": record.get("kind", ""),
        "severity": record.get("severity", ""),
        "attribution": attribution,
        "source": record.get("source", ""),
        "faultcore_involved": involved,
        "pid": record.get("pid") or coredump.get("pid"),
        "comm": record.get("comm") or coredump.get("comm", ""),
        "exe": record.get("exe") or coredump.get("exe", ""),
        "component": component,
        "sig": coredump.get("signal_name") or record.get("kind", "crash"),
        "cpus_allowed": cpus,
        "corefile": coredump.get("core_path") or str(incident_dir),
        "incident_dir": str(incident_dir),
        "fault_cpus": list((record.get("faultlab") or {}).get("fault_cpus") or []),
        "context": _feed_context(record, incident_dir),
    }


def append_qa_feed(
    path: Path, payload: Mapping[str, Any], system: bool
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+", encoding="utf-8") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        fh.write(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    try:
        os.chmod(path, 0o640 if system else 0o600)
        if system:
            try:
                gid = grp.getgrnam("adm").gr_gid
            except KeyError:
                gid = 0
            os.chown(path, 0, gid)
    except OSError:
        pass


def record_qa_feed(
    store: IncidentStore,
    record: Mapping[str, Any],
    incident_dir: Path,
    system: bool,
) -> None:
    if os.environ.get("FAULTLAB_CRASH_QA", "1") != "1":
        return
    path = qa_feed_path(store, system)
    payload = qa_feed_record(record, incident_dir)
    append_qa_feed(path, payload, system)
    state = store.load_state("qa-feed.json", {})
    if state.get("path") != str(path):
        state = {"path": str(path), "ids": []}
    ids = set(str(item) for item in state.get("ids") or [])
    ids.add(str(payload["id"]))
    state["ids"] = sorted(ids)
    store.save_state("qa-feed.json", state)


def backfill_qa_feed(store: IncidentStore, system: bool) -> int:
    """Feed incidents created before the collector wrote the QA feed."""
    if os.environ.get("FAULTLAB_CRASH_QA", "1") != "1":
        return 0
    path = qa_feed_path(store, system)
    state = store.load_state("qa-feed.json", {})
    if state.get("path") != str(path):
        state = {"path": str(path), "ids": []}
    ids = set(str(item) for item in state.get("ids") or [])
    added = 0

    def sort_key(item: Path) -> float:
        try:
            return (item / "incident.json").stat().st_mtime
        except OSError:
            return 0.0

    directories = sorted(store.incident_dirs(), key=sort_key)
    for directory in directories:
        if directory.name in ids:
            continue
        try:
            record = json.loads(read_text(directory / "incident.json"))
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        record = dict(record)
        record["id"] = directory.name
        try:
            append_qa_feed(path, qa_feed_record(record, directory), system)
        except OSError:
            break
        ids.add(directory.name)
        added += 1
    state["ids"] = sorted(ids)
    store.save_state("qa-feed.json", state)
    return added


def build_capture_files(
    ctx: FaultContext,
    record: Mapping[str, Any],
    info: CoredumpInfo | None,
    system: bool,
) -> dict[str, str | bytes]:
    files: dict[str, str | bytes] = {
        "topology.txt": capture_topology(ctx),
        "dmesg.txt": capture_dmesg(),
        "ras.txt": capture_ras(system),
        "processes.txt": capture_processes(ctx),
        "sensors.txt": capture_sensors(),
        "journal.txt": capture_journal_context(
            str(record.get("boot_id", "")),
            float(record.get("created_ts", utc_now())),
            float(record.get("last_seen_ts", utc_now())),
        ),
    }
    if info is not None:
        files.update(capture_coredump(ctx, info, system))
    return files


# ---------------------------------------------------------------------------
# Boot-log analysis for pstore / kdump


_BOOT_TRIGGER_RE = re.compile(
    r"(?i)\b(?:kernel panic|panic occurred|oops|kernel bug at|"
    r"bug:\s*(?:unable|kernel)|general protection fault|invalid opcode|"
    r"machine check|hardware error|mce:|soft lockup|hard lockup|"
    r"watchdog:\s*bug|rcu.*stall|call trace)\b"
)


def analyse_bootlog(text: str) -> tuple[Trigger, set[int], str, str] | None:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not _BOOT_TRIGGER_RE.search(line):
            continue
        trigger = classify_kernel_line(line) or Trigger(
            "panic" if "panic" in line.lower() else "oops",
            "critical",
            "boot-log",
        )
        start = max(0, index - 80)
        end = min(len(lines), index + 120)
        excerpt = "\n".join(lines[start:end])
        cpus = cpus_in_text(excerpt)
        return trigger, cpus, excerpt, line
    return None


def static_incident(
    ctx: FaultContext,
    store: IncidentStore,
    *,
    source: str,
    trigger: Trigger,
    message: str,
    excerpt: str,
    boot_id: str,
    created_ts: float,
    files: Mapping[str, str | bytes],
    system: bool,
) -> Path:
    cpus = cpus_in_text(excerpt)
    matched = cpus & set(ctx.fault_cpus)
    if matched:
        attribution = "direct"
    elif trigger.kind in ("panic", "mce"):
        attribution = "possible"
    else:
        attribution = "none"
    digest = hashlib.sha256(
        make_signature(trigger.kind, cpus, message).encode()
    ).hexdigest()[:8]
    stamp = datetime.fromtimestamp(
        created_ts, timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")
    record = {
        "schema": SCHEMA,
        "id": f"{stamp}-{trigger.kind}-{digest}",
        "created": iso(created_ts),
        "created_ts": created_ts,
        "last_seen": iso(created_ts),
        "last_seen_ts": created_ts,
        "occurrences": 1,
        "boot_id": boot_id,
        "source": source,
        "kind": trigger.kind,
        "severity": trigger.severity,
        "attribution": attribution,
        "signature": make_signature(trigger.kind, cpus, message),
        "trigger": trigger.reason,
        "matched_cpus": sorted(matched),
        "event_cpus": sorted(cpus),
        "pid": None,
        "comm": "",
        "exe": "",
        "cgroup": "",
        "unit": "",
        "trigger_lines": [{"ts": iso(created_ts), "message": redact(message)[:4000]}],
        "coredump": {},
        "faultlab": ctx.public_dict(),
        "redaction": "credentials, environment blocks and command lines withheld",
        "host": {
            "hostname": os.uname().nodename,
            "kernel": os.uname().release,
            "boot_id": read_text("/proc/sys/kernel/random/boot_id").strip(),
            "microcode": _microcode(),
        },
    }
    payload = dict(files)
    payload.setdefault("topology.txt", capture_topology(ctx))
    payload.setdefault("ras.txt", capture_ras(system))
    path = store.create(record, payload)
    try:
        record = dict(record)
        record["id"] = path.name
        record_qa_feed(store, record, path, system)
    except OSError:
        pass
    return path
