"""Integration tests for the crash daemon's burst manager."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import time
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
loader = SourceFileLoader(
    "faultlab_crashd", str(ROOT / "bin" / "faultlab-crashd")
)
spec = importlib.util.spec_from_loader("faultlab_crashd", loader)
assert spec is not None
crashd = importlib.util.module_from_spec(spec)
loader.exec_module(crashd)

from faultlab_crash import FaultContext, IncidentStore  # noqa: E402


def event(message: str, now: float, **extra: str) -> dict:
    payload = {
        "MESSAGE": message,
        "__REALTIME_TIMESTAMP": str(int(now * 1_000_000)),
        "_BOOT_ID": "boot",
        "_PID": "10",
        "_COMM": "probe",
        "_TRANSPORT": "kernel",
        "_SYSTEMD_CGROUP": "/system.slice/probe.service",
        "_SYSTEMD_UNIT": "probe.service",
    }
    payload.update(extra)
    return payload


class ManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = Path(tempfile.mkdtemp(prefix="faultlab-manager-"))
        self.store = IncidentStore(self.temp, system=False)
        self.store.ensure()
        self.ctx = FaultContext(
            fault_cpu=2, fault_cpus=(2, 8), mode="lab"
        )
        self.manager = crashd.Manager(
            self.ctx,
            self.store,
            system=False,
            burst_seconds=5,
            dedup_seconds=300,
            collect_all=False,
        )
        self.patch = mock.patch.object(
            crashd, "build_capture_files", return_value={}
        )
        self.patch.start()

    def tearDown(self) -> None:
        self.patch.stop()
        import shutil

        shutil.rmtree(self.temp, ignore_errors=True)

    def test_kernel_mce_creates_incident(self) -> None:
        now = time.time()
        self.manager.feed(
            event(
                "mce: [Hardware Error]: CPU: 2 MC4_STATUS[Over|CE]",
                now,
            )
        )
        self.manager.finalize()
        rows = self.store.read_index()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "mce")
        self.assertEqual(rows[0]["attribution"], "direct")
        self.assertEqual(rows[0]["matched_cpus"], [2])

    def test_other_cpu_warning_is_dropped(self) -> None:
        now = time.time()
        self.manager.feed(
            event("WARNING: CPU: 1 PID: 7 at foo.c:10", now)
        )
        self.manager.finalize()
        self.assertEqual(self.store.read_index(), [])

    def test_rasdaemon_tracepoint_control_is_ignored(self) -> None:
        now = time.time()
        for message in (
            "rasdaemon: mce:mce_record event enabled",
            "rasdaemon: Enabled event mce:mce_record",
            "Enabled event cxl:cxl_poison",
        ):
            self.manager.feed(event(message, now))
        self.manager.finalize()
        self.assertEqual(self.store.read_index(), [])

    def test_coredump_outside_faultlab_is_dropped(self) -> None:
        now = time.time()
        self.manager.feed(
            event(
                "Process 10 (probe) dumped core.",
                now,
                COREDUMP_PID="10",
                COREDUMP_CGROUP="/user.slice/x.service",
                COREDUMP_PROC_STATUS="Cpus_allowed_list:\t0-1,3-7,9-11\n",
                COREDUMP_SIGNAL="11",
                COREDUMP_EXE="/tmp/probe",
                _TRANSPORT="journal",
            )
        )
        self.manager.finalize()
        self.assertEqual(self.store.read_index(), [])

    def test_coredump_in_faultlab_is_stored(self) -> None:
        now = time.time()
        self.manager.feed(
            event(
                "Process 10 (probe) dumped core.",
                now,
                COREDUMP_PID="10",
                COREDUMP_CGROUP="/faultlab.slice/faultlab-10.service",
                COREDUMP_PROC_STATUS="Cpus_allowed_list:\t2,8\n",
                COREDUMP_SIGNAL="11",
                COREDUMP_EXE="/tmp/probe",
                COREDUMP_TIMESTAMP=str(int(now * 1_000_000)),
                _TRANSPORT="journal",
            )
        )
        self.manager.finalize()
        rows = self.store.read_index()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "coredump")
        self.assertEqual(rows[0]["attribution"], "direct")

    def test_repeat_merges_into_one_folder(self) -> None:
        now = time.time()
        message = "mce: [Hardware Error]: CPU: 2 MC4_STATUS[Over|CE]"
        self.manager.feed(event(message, now))
        self.manager.finalize()
        time.sleep(0.01)
        self.manager.feed(event(message, now + 1))
        self.manager.finalize()
        rows = self.store.read_index()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["occurrences"], 2)
        path = self.temp / rows[0]["dir"]
        self.assertTrue((path / "occurrences.jsonl").is_file())

    def test_backlog_burst_survives_tick(self) -> None:
        old = time.time() - 300
        self.manager.feed(
            event("mce: [Hardware Error]: CPU: 2 MC4_STATUS[Over|CE]", old)
        )
        self.manager.tick(time.time())
        self.assertIsNotNone(self.manager.active)
        self.manager.feed(event("RIP: 0010:probe+0x10/0x20", old + 1))
        self.manager.finalize()
        rows = self.store.read_index()
        self.assertEqual(len(rows), 1)

    def test_secret_is_not_persisted(self) -> None:
        now = time.time()
        self.manager.feed(
            event(
                "mce: CPU: 2 TOKEN=super-secret-value",
                now,
            )
        )
        self.manager.finalize()
        for path in self.temp.rglob("*"):
            if path.is_file():
                self.assertNotIn(
                    "super-secret-value", path.read_text(errors="replace")
                )


if __name__ == "__main__":
    unittest.main()
