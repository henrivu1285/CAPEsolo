"""Refresh presentation after finalizer completion without re-running detectors."""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from CAPEsolo.capelib.analysis_quality import collect_quality, read_json
from CAPEsolo.capelib.evidence_snapshot import REVISION, behavior_digest, identity, validate_snapshot


def refresh_report_quality(analysis_dir, finalizer):
    from CAPEsolo.capelib.capa_integration import atomic_json
    from CAPEsolo.capelib.report_redaction import redact_report_in_place
    from CAPEsolo.capelib.threat_assessment import assess_threat
    base = Path(analysis_dir)
    status = {"processor_revision": REVISION, "updated_utc": datetime.now(timezone.utc).isoformat(),
              "detectors_rerun": False, "html": "not_present"}
    try:
        results = read_json(base / "report.json")
        if not results:
            status["status"] = "report_unavailable"
            return status
        runtime = read_json(base / "frida_p3_runtime.json")
        current = identity(results, runtime)
        final_id = (finalizer.get("run") or {}).get("run_id")
        if current["run_id"] and final_id != current["run_id"]:
            raise ValueError("finalizer_run_id_mismatch")
        validate_snapshot(base, results, runtime)
        results["analysis_quality"] = collect_quality(results, base, finalizer)
        results["threat_assessment"] = assess_threat(results)
        redact_report_in_place(results)
        atomic_json(base / "analysis_quality.json", results["analysis_quality"])
        atomic_json(base / "report.json", results)
        desktop = Path.home() / "Desktop" / "report.json"
        if desktop.is_file() and desktop.resolve() != (base / "report.json").resolve():
            old_desktop = read_json(desktop)
            if identity(old_desktop, runtime) == current and behavior_digest(old_desktop) == behavior_digest(results):
                try:
                    atomic_json(desktop, results)
                    status["desktop_json"] = "refreshed_same_behavior"
                except OSError as exc:
                    status["desktop_json_warning"] = str(exc)
            else:
                status["desktop_json"] = "different_report_preserved"
        if results.get("mitre_attack"):
            atomic_json(base / "mitre_attack.json", results["mitre_attack"])
        if (base / "report.html").is_file():
            from CAPEsolo.classes.html_report import ReportHTML
            ok, error = ReportHTML().run(base, Path(__file__).resolve().parents[1], results)
            status["html"] = "refreshed" if ok else "refresh_failed"
            if not ok:
                status["html_error"] = str(error)
        status["status"] = "partial" if status["html"] == "refresh_failed" else "ok"
    except Exception as exc:
        status.update(status="refresh_failed", reason=f"{type(exc).__name__}: {exc}")
    finally:
        atomic_json(base / "report_refresh.json", status)
    return status
