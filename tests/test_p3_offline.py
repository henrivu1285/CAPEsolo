from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "lib" / "common"
TOOLS = ROOT / "tools"
for path in (LIB, TOOLS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from frida_profile_resolver import resolve_profile  # noqa: E402
from frida_artifact_filter import classify_analysis  # noqa: E402
from frida_p3_finalize import build_report  # noqa: E402


class P3OfflineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_profile_auto_blackenergy_without_hash_dependency(self):
        # Match by the conservative combination name + size + gate bytes.
        analysis = self.base / "sample"
        analysis.mkdir()
        sample = analysis / "rootkit.exe"
        data = bytearray(76288)
        data[:7] = bytes.fromhex("4d5aebfe1f0100")
        sample.write_bytes(data)

        result = resolve_profile(
            profile_dir=ROOT / "data" / "frida_profiles",
            analysis_dir=analysis,
            requested="auto",
        )
        self.assertEqual(result["selected"], "blackenergy21")
        self.assertGreaterEqual(result["score"], 80)

    def test_profile_auto_unknown_falls_back_generic(self):
        analysis = self.base / "unknown"
        analysis.mkdir()
        (analysis / "unknown.exe").write_bytes(b"MZ" + b"\x00" * 200)
        result = resolve_profile(
            profile_dir=ROOT / "data" / "frida_profiles",
            analysis_dir=analysis,
            requested="auto",
        )
        self.assertEqual(result["selected"], "generic")
        self.assertEqual(result["source"], "fallback")

    def test_artifact_filter_keeps_unknown_and_filters_frida(self):
        analysis = self.base / "analysis"
        cape = analysis / "CAPE"
        cape.mkdir(parents=True)
        frida_hash = "a" * 64
        unknown_hash = "b" * 64
        (cape / frida_hash).write_bytes(b"xx frida_agent_main yy")
        (cape / unknown_hash).write_bytes(b"MZ" + b"A" * 64)
        (analysis / "files.json").write_text(
            "\n".join(
                [
                    json.dumps({"path": f"CAPE/{frida_hash}", "metadata": "9;?x;?x;?0x1000;?", "category": "CAPE"}),
                    json.dumps({"path": f"CAPE/{unknown_hash}", "metadata": "8;?x;?x;?0x2000;?", "category": "CAPE"}),
                ]
            ),
            encoding="utf-8",
        )
        (analysis / "analysis.log").write_text("", encoding="utf-8")
        result = classify_analysis(analysis)
        self.assertEqual(result["summary"]["instrumentation"], 1)
        self.assertEqual(result["summary"]["retained"], 1)
        filtered = (analysis / "files.filtered.jsonl").read_text(encoding="utf-8")
        self.assertIn(unknown_hash, filtered)
        self.assertNotIn(frida_hash, filtered)

    def test_finalizer_marks_resultserver_incomplete_as_degraded(self):
        analysis = self.base / "result"
        (analysis / "CAPE").mkdir(parents=True)
        (analysis / "files.json").write_text("", encoding="utf-8")
        (analysis / "analysis.log").write_text(
            "\n".join(
                [
                    "[FridaMuncher][pid=1] Root instrumentation ready; queued child attaches may proceed.",
                    "[classes.start_panel] INFO: Run completed",
                    "[CAPEsolo.capelib.resultserver] ERROR: ResultServer transfers complete=3 incomplete=1 - some analysis data was NOT stored",
                ]
            ),
            encoding="utf-8",
        )
        report = build_report(analysis)
        self.assertEqual(report["status"], "degraded")
        self.assertEqual(report["integrity"]["resultserver"]["incomplete_transfers"], 1)


if __name__ == "__main__":
    unittest.main()
