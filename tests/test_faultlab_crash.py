"""Unit tests for the faultlab crash collector helpers."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from faultlab_crash import (  # noqa: E402
    Burst,
    CoredumpInfo,
    FaultContext,
    IncidentStore,
    Trigger,
    analyse_bootlog,
    backfill_qa_feed,
    classify_kernel_line,
    cpu_expand,
    cpu_text,
    cpus_in_text,
    filter_coredump_info,
    make_signature,
    qa_feed_record,
    redact,
)


class CpuTests(unittest.TestCase):
    def test_expand(self) -> None:
        self.assertEqual(cpu_expand("2,8"), [2, 8])
        self.assertEqual(cpu_expand("0-3,8"), [0, 1, 2, 3, 8])
        self.assertEqual(cpu_expand("3-1"), [])
        self.assertEqual(cpu_expand(""), [])

    def test_text(self) -> None:
        self.assertEqual(cpu_text([2, 8]), "2,8")
        self.assertEqual(cpu_text([0, 1, 2, 3, 8]), "0-3,8")

    def test_parse_cpu_from_messages(self) -> None:
        self.assertEqual(cpus_in_text("CPU: 2 PID: 10"), {2})
        self.assertEqual(cpus_in_text("watchdog: BUG: soft lockup - CPU#2"), {2})
        self.assertEqual(cpus_in_text("rcu: 2-...!: (0 ticks)"), {2})
        self.assertEqual(cpus_in_text("no cpu here"), set())


class ClassifyTests(unittest.TestCase):
    def test_mce(self) -> None:
        trigger = classify_kernel_line(
            "mce: [Hardware Error]: CPU: 2 MC4_STATUS[Over|CE]: 0xbe"
        )
        self.assertIsNotNone(trigger)
        assert trigger is not None
        self.assertEqual(trigger.kind, "mce")
        self.assertEqual(trigger.severity, "warning")

    def test_uncorrected_mce(self) -> None:
        trigger = classify_kernel_line(
            "mce: [Hardware Error]: Uncorrected error, CPU: 2"
        )
        assert trigger is not None
        self.assertEqual(trigger.severity, "critical")

    def test_decoding_is_not_a_crash(self) -> None:
        self.assertIsNone(
            classify_kernel_line("MCE: In-kernel MCE decoding enabled.")
        )

    def test_rasdaemon_tracepoint_control_is_not_a_crash(self) -> None:
        for message in (
            "rasdaemon: mce:mce_record event enabled",
            "rasdaemon: mce:mce_record event disabled",
            "rasdaemon: Enabled event mce:mce_record",
            "Enabled event mce:mce_record",
            "Enabled event cxl:cxl_poison",
            "rasdaemon: cxl:cxl_aer_uncorrectable_error event enabled",
        ):
            with self.subTest(message=message):
                self.assertIsNone(classify_kernel_line(message))

    def test_lockup(self) -> None:
        trigger = classify_kernel_line(
            "watchdog: BUG: soft lockup - CPU#2 stuck for 22s!"
        )
        assert trigger is not None
        self.assertEqual(trigger.kind, "lockup")

    def test_panic(self) -> None:
        trigger = classify_kernel_line("Kernel panic - not syncing: Fatal exception")
        assert trigger is not None
        self.assertEqual(trigger.kind, "panic")
        self.assertEqual(trigger.severity, "critical")

    def test_other_cpu_warning(self) -> None:
        trigger = classify_kernel_line("WARNING: CPU: 1 PID: 4 at foo.c:10")
        assert trigger is not None
        self.assertEqual(trigger.kind, "warning")

    def test_segfault(self) -> None:
        trigger = classify_kernel_line("traps: probe[123] general protection fault ip:...")
        assert trigger is not None
        self.assertEqual(trigger.kind, "oops")


class RedactionTests(unittest.TestCase):
    def test_secret_assignment(self) -> None:
        text = "DEEPSEEK_API_KEY=sk-test0123456789abcdef and TOKEN=abc123"
        clean = redact(text)
        self.assertNotIn("sk-test0123456789abcdef", clean)
        self.assertNotIn("abc123", clean)
        self.assertIn("<redacted>", clean)

    def test_json_secret(self) -> None:
        clean = redact('{"api_key": "sk-test0123456789abcdef"}')
        self.assertNotIn("sk-test0123456789abcdef", clean)

    def test_network_identifiers(self) -> None:
        clean = redact(
            "MAC 14:f6:d8:9d:0b:98 SRC=192.168.1.5 IPv6 fe80::1"
        )
        self.assertNotIn("14:f6:d8:9d:0b:98", clean)
        self.assertNotIn("192.168.1.5", clean)
        self.assertNotIn("fe80::1", clean)

    def test_timestamp_is_not_ipv6(self) -> None:
        self.assertEqual(redact("10:37:39"), "10:37:39")

    def test_systemd_unit_is_not_email(self) -> None:
        text = "Control Group: /user.slice/user-1000.slice/user@1000.service"
        self.assertEqual(redact(text), text)
        text = "org.gnome.Shell@x11.service"
        self.assertEqual(redact(text), text)

    def test_email_is_redacted(self) -> None:
        self.assertIn("<email>", redact("contact gerard@example.com"))

    def test_control_characters_removed(self) -> None:
        self.assertEqual(redact("a\x1b[31mb\x00c"), "a[31mbc")

    def test_private_key(self) -> None:
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "abcdef\n"
            "-----END RSA PRIVATE KEY-----"
        )
        self.assertEqual(redact(text), "<redacted-private-key>")


class CoredumpTests(unittest.TestCase):
    event = {
        "COREDUMP_PID": "4242",
        "COREDUMP_UID": "0",
        "COREDUMP_GID": "0",
        "COREDUMP_SIGNAL": "11",
        "COREDUMP_SIGNAL_NAME": "SIGSEGV",
        "COREDUMP_COMM": "probe",
        "COREDUMP_EXE": "/tmp/probe",
        "COREDUMP_CGROUP": "/faultlab.slice/faultlab-42.service",
        "COREDUMP_UNIT": "faultlab-42.service",
        "COREDUMP_SLICE": "faultlab.slice",
        "COREDUMP_FILENAME": "/var/lib/systemd/coredump/core.probe.0.x.4242.1.zst",
        "COREDUMP_TIMESTAMP": "1700000000000000",
        "COREDUMP_PROC_STATUS": "Name:\tprobe\nCpus_allowed_list:\t2,8\n",
        "COREDUMP_ENVIRON": "DEEPSEEK_API_KEY=sk-test0123456789abcdef",
        "COREDUMP_CMDLINE": "/tmp/probe --token=secret",
        "MESSAGE": "Process 4242 (probe) dumped core.\nStack trace of thread 4242:",
        "_BOOT_ID": "boot",
    }

    def test_whitelist(self) -> None:
        info = CoredumpInfo.from_event(self.event)
        public = json.dumps(info.public_dict())
        self.assertNotIn("sk-test", public)
        self.assertNotIn("secret", public)
        self.assertNotIn("DEEPSEEK", public)
        self.assertEqual(info.cpus_allowed, "2,8")
        self.assertTrue(info.is_faultlab)
        self.assertEqual(info.allowed_cpus(), {2, 8})

    def test_filter_info(self) -> None:
        text = (
            "           PID: 1\n"
            "  Command Line: /bin/foo --password=hunter2\n"
            "                /bin/foo --more\n"
            "    Executable: /bin/foo\n"
            "       Message: dumped core\n"
        )
        clean = filter_coredump_info(text)
        self.assertNotIn("hunter2", clean)
        self.assertNotIn("--more", clean)
        self.assertIn("Executable", clean)
        self.assertIn("Message", clean)


class BurstTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ctx = FaultContext(
            fault_cpu=2,
            fault_cpus=(2, 8),
            control_cpus=(1, 7),
            safe_cpus=(0, 1, 3, 4, 5, 6, 7, 9, 10, 11),
            mode="lab",
        )

    def test_direct_event(self) -> None:
        burst = Burst(boot_id="b", first_ts=time.time(), last_ts=time.time())
        burst.add_trigger(
            Trigger("mce", "warning", "x"),
            "mce: CPU: 2 error",
            time.time(),
            1,
            "x",
            "/system.slice/x.service",
            "x.service",
            {2},
        )
        attr = burst.attribution(self.ctx, False)
        self.assertEqual(attr, "direct")
        self.assertEqual(burst.matched_cpus, {2})
        self.assertTrue(burst.should_store(attr, False))

    def test_other_cpu_mce_is_kept(self) -> None:
        burst = Burst(boot_id="b", first_ts=time.time(), last_ts=time.time())
        burst.add_trigger(
            Trigger("mce", "warning", "x"),
            "mce: CPU: 1 error",
            time.time(),
            1,
            "x",
            "",
            "",
            {1},
        )
        attr = burst.attribution(self.ctx, False)
        self.assertEqual(attr, "other-cpu")
        self.assertTrue(burst.should_store(attr, False))

    def test_lab_oops_on_other_cpu_is_possible(self) -> None:
        burst = Burst(boot_id="b", first_ts=time.time(), last_ts=time.time())
        burst.add_trigger(
            Trigger("oops", "critical", "x"),
            "Oops: 0000 [#1] CPU: 1 PID: 7",
            time.time(),
            1,
            "x",
            "",
            "",
            {1},
        )
        with mock.patch.object(
            FaultContext, "current_mode", return_value="lab"
        ):
            attr = burst.attribution(self.ctx, False)
        self.assertEqual(attr, "possible")
        self.assertTrue(burst.should_store(attr, False))

    def test_retired_oops_on_other_cpu_is_dropped(self) -> None:
        burst = Burst(boot_id="b", first_ts=time.time(), last_ts=time.time())
        burst.add_trigger(
            Trigger("oops", "critical", "x"),
            "Oops: 0000 [#1] CPU: 1 PID: 7",
            time.time(),
            1,
            "x",
            "",
            "",
            {1},
        )
        with mock.patch.object(
            FaultContext, "current_mode", return_value="retired"
        ):
            attr = burst.attribution(self.ctx, False)
        self.assertEqual(attr, "none")

    def test_coredump_outside_faultlab_is_ignored(self) -> None:
        burst = Burst(boot_id="b", first_ts=time.time(), last_ts=time.time())
        burst.add_coredump(
            CoredumpInfo(
                pid=1,
                cgroup="/user.slice/x.service",
                cpus_allowed="0-1,3-7,9-11",
                signal_name="SIGSEGV",
            )
        )
        attr = burst.attribution(self.ctx, False)
        self.assertEqual(attr, "none")
        self.assertFalse(burst.should_store(attr, False))

    def test_coredump_in_faultlab_is_direct(self) -> None:
        burst = Burst(boot_id="b", first_ts=time.time(), last_ts=time.time())
        burst.add_coredump(
            CoredumpInfo(
                pid=1,
                cgroup="/faultlab.slice/faultlab-1.service",
                cpus_allowed="2,8",
                signal_name="SIGSEGV",
            )
        )
        attr = burst.attribution(self.ctx, False)
        self.assertEqual(attr, "direct")

    def test_signature_stable(self) -> None:
        first = make_signature("oops", {2}, "RIP: 0x1234 pid 42")
        second = make_signature("oops", {2}, "RIP: 0x9999 pid 99")
        self.assertEqual(first, second)


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = Path(tempfile.mkdtemp(prefix="faultlab-test-"))
        self.store = IncidentStore(self.temp, system=False)
        self.store.ensure()
        self.ctx = FaultContext(
            fault_cpu=2, fault_cpus=(2, 8), mode="lab"
        )

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.temp, ignore_errors=True)

    def _record(self, offset: float = 0) -> dict:
        now = time.time() + offset
        burst = Burst(boot_id="boot", first_ts=now, last_ts=now)
        burst.add_trigger(
            Trigger("mce", "warning", "x"),
            "mce: CPU: 2 DEEPSEEK_API_KEY=sk-test0123456789abcdef",
            now,
            1,
            "probe",
            "/faultlab.slice/x.service",
            "x.service",
            {2},
        )
        return burst.record(self.ctx, "direct")

    def test_roundtrip_and_redaction(self) -> None:
        record = self._record()
        path = self.store.create(
            record, {"journal.txt": "TOKEN=super-secret-value"}
        )
        self.assertTrue((path / "incident.json").is_file())
        self.assertTrue((path / "checksums.sha256").is_file())
        for file in path.rglob("*"):
            if file.is_file():
                text = file.read_text(errors="replace")
                self.assertNotIn("sk-test0123456789abcdef", text)
                self.assertNotIn("super-secret-value", text)
        self.assertEqual(self.store.verify(path.name), [])
        self.assertEqual(len(self.store.read_index()), 1)
        self.assertEqual(self.store.resolve("latest"), path)
        self.assertEqual([x.name for x in self.store.incident_dirs()], [path.name])

    def test_recent_dedup(self) -> None:
        record = self._record()
        self.store.create(record, {})
        self.assertIsNotNone(
            self.store.recent("boot", record["signature"], 300)
        )
        self.assertIsNone(self.store.recent("other", record["signature"], 300))

    def test_update_occurrence(self) -> None:
        record = self._record()
        path = self.store.create(record, {})
        record["occurrences"] = 2
        record["last_seen_ts"] = time.time() + 1
        self.store.append_occurrence(path.name, {"ts": "now"})
        self.store.update(path.name, record)
        updated = json.loads((path / "incident.json").read_text())
        self.assertEqual(updated["occurrences"], 2)
        self.assertEqual(self.store.verify(path.name), [])

    def test_qa_feed_record_captures_component_without_secrets(self) -> None:
        record = self._record()
        path = self.store.create(record, {})
        payload = qa_feed_record(record, path)
        self.assertEqual(payload["schema"], "faultlab.crash.qa/1")
        self.assertEqual(payload["component"], "probe")
        self.assertEqual(payload["faultcore_involved"], 1)
        self.assertIn("CPU: 2", payload["context"])
        self.assertIn("fault_core=fault core (CPUs 2,8", payload["context"])
        self.assertNotIn("unattributed", payload["context"])
        self.assertNotIn("sk-test0123456789abcdef", json.dumps(payload))

    def test_qa_feed_context_does_not_invent_fault_core(self) -> None:
        now = time.time()
        burst = Burst(boot_id="boot", first_ts=now, last_ts=now)
        burst.add_trigger(
            Trigger("mce", "warning", "x"),
            "mce: [Hardware Error]: no CPU named",
            now,
            None,
            "rasdaemon",
            "/system.slice/rasdaemon.service",
            "rasdaemon.service",
            set(),
        )
        record = burst.record(self.ctx, "possible")
        path = self.store.create(record, {})
        payload = qa_feed_record(record, path)
        self.assertIn("fault_core=unattributed", payload["context"])
        self.assertIn("matched_cpus=[]", payload["context"])
        self.assertNotIn("fault_core=fault core (CPUs 2,8", payload["context"])

    def test_qa_feed_backfill_is_idempotent(self) -> None:
        record = self._record()
        path = self.store.create(record, {})
        feed = self.temp / "qa.jsonl"
        with mock.patch.dict(
            os.environ, {"FAULTLAB_CRASH_QA_FEED": str(feed)}, clear=False
        ):
            self.assertEqual(backfill_qa_feed(self.store, False), 1)
            self.assertEqual(backfill_qa_feed(self.store, False), 0)
        lines = feed.read_text().splitlines()
        self.assertEqual(len(lines), 1)
        payload = json.loads(lines[0])
        self.assertEqual(payload["id"], path.name)
        self.assertEqual(payload["component"], "probe")

    def test_prune_keeps_newest(self) -> None:
        first = self.store.create(self._record(), {})
        second = self.store.create(self._record(offset=2), {})
        removed = self.store.prune(keep=1, max_mb=2048, dry_run=False)
        self.assertEqual([path.name for path in removed], [first.name])
        self.assertFalse(first.exists())
        self.assertTrue(second.exists())

    def test_bootlog(self) -> None:
        result = analyse_bootlog(
            "\n".join(
                ["normal boot line"] * 10
                + ["Kernel panic - not syncing: CPU: 2 stuck"]
                + ["trace line"] * 5
            )
        )
        self.assertIsNotNone(result)
        assert result is not None
        trigger, cpus, excerpt, line = result
        self.assertEqual(trigger.kind, "panic")
        self.assertIn(2, cpus)
        self.assertIn("Kernel panic", excerpt)
        self.assertIn("Kernel panic", line)


if __name__ == "__main__":
    unittest.main()
