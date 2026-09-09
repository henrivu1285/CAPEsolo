"""Deterministic attach diagnostics; error classification does not infer cause."""
from __future__ import annotations
import copy
import re


def process_is_terminating(error):
    return bool(re.search(r"(?i)(?<![0-9a-f])0xc000010a(?![0-9a-f])|\bSTATUS_PROCESS_IS_TERMINATING\b", str(error)))


def classify_attach_failure(error, alive):
    if process_is_terminating(error):
        return "process_terminating"
    return "failed_exception" if alive else "target_died"


def normalize_attach_events(events):
    """Enrich copies of historical records; preserve the original acquisition."""
    output = copy.deepcopy(events)
    terminating = set()
    for event in output:
        pid = event.get("pid")
        if event.get("kind") == "frida_attach":
            if event.get("status") == "success":
                terminating.discard(pid)
            elif process_is_terminating(event.get("error")):
                event["acquisition_status"] = event.get("status")
                event["status"] = "process_terminating"
                event["diagnostic_reason"] = "STATUS_PROCESS_IS_TERMINATING"
                terminating.add(pid)
        elif event.get("kind") == "frida_process_outcome" and pid in terminating and event.get("phase") == "attach":
            event["acquisition_status"] = event.get("status")
            event["status"] = "process_terminating_during_attach"
            event["attach_status"] = "process_terminating"
            event["termination_cause"] = "undetermined"
    return output
