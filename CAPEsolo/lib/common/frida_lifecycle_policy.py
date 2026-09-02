"""Pure P3.2.3.7 lifecycle/synchronization policy helpers.

Kept independent from CAPEsolo/Frida imports so it can be regression-tested
without a live sandbox.  The helpers make policy decisions only; they do not
attach, inject, or modify a target process.
"""
from __future__ import annotations

import re

CAPEMON_READY_PATTERNS = (
    ("monitor_loaded", re.compile(r"\bLoaded monitor into process with pid\s+{pid}\b", re.I)),
    ("syscall_hook_installed", re.compile(r"\b{pid}:\s+Syscall hook installed\b", re.I)),
    ("hook_set_complete", re.compile(r"\b{pid}:\s+Hooked\s+\d+\s+out of\s+\d+\s+functions\b", re.I)),
)


def detect_capemon_ready_signal(log_text: str, pid: int) -> str | None:
    """Return a conservative CAPEMON-ready signal for *pid*, if present."""
    text = str(log_text or "")
    pid_text = re.escape(str(int(pid)))
    for name, template in CAPEMON_READY_PATTERNS:
        pattern = re.compile(template.pattern.format(pid=pid_text), template.flags)
        if pattern.search(text):
            return name
    return None


def child_priority_decision(
    *,
    root_ready: bool,
    root_alive: bool,
    root_failed: bool,
    elapsed: float,
    priority_window: float,
) -> str:
    """Decide whether a child should keep yielding to the root attach.

    Returns one of:
      - ``root_ready``: root instrumentation completed; child may continue.
      - ``promote_root_unavailable``: root died/failed; child should continue now.
      - ``promote_priority_window_elapsed``: bounded root-priority window elapsed.
      - ``wait``: briefly keep yielding to the root.

    The policy intentionally never waits indefinitely for a short-lived root.
    """
    if root_ready:
        return "root_ready"
    if root_failed or not root_alive:
        return "promote_root_unavailable"
    if float(elapsed) >= max(0.0, float(priority_window)):
        return "promote_priority_window_elapsed"
    return "wait"


CHILD_ATTACH_POLICIES = frozenset({"adaptive", "immediate", "capemon_only"})


def advance_active_observation(
    *,
    active_elapsed: float,
    scheduler_gap_elapsed: float,
    delta: float,
    max_tick: float,
) -> tuple[float, float, bool]:
    """Advance a child observation clock without charging scheduler stalls.

    Normal short polling intervals count toward ``active_elapsed``. A delay
    larger than ``max_tick`` is treated as a scheduler/VM stall and is reported
    separately. This prevents an adaptive policy from consuming its complete
    CAPEMON-exclusive budget while the lifecycle worker was not scheduled.
    """
    active = max(0.0, float(active_elapsed))
    stalled = max(0.0, float(scheduler_gap_elapsed))
    step = max(0.0, float(delta))
    threshold = max(0.001, float(max_tick))
    if step > threshold:
        return active, stalled + step, True
    return active + step, stalled, False


def normalize_child_attach_policy(value: object, default: str = "adaptive") -> str:
    """Return a supported generic child-attach policy.

    ``adaptive`` gives CAPEMON an exclusive observation window and attaches
    Frida only when the child survives it. ``immediate`` preserves the older
    immediate-attach behavior for explicitly validated profiles. ``capemon_only`` keeps
    descendant discovery and Sysmon correlation but deliberately skips Frida.
    """
    fallback = str(default or "adaptive").strip().lower()
    if fallback not in CHILD_ATTACH_POLICIES:
        fallback = "adaptive"
    policy = str(value or fallback).strip().lower()
    return policy if policy in CHILD_ATTACH_POLICIES else fallback


def child_attach_decision(
    *,
    policy: str,
    alive: bool,
    elapsed: float,
    exclusive_window: float,
) -> str:
    """Decide whether a discovered child should be attached now.

    The function is process-family agnostic. It uses only the configured
    policy, liveness and elapsed CAPEMON-owned observation time.

    Returns one of ``attach_now``, ``wait_exclusive_window``,
    ``capemon_only`` or ``target_exited_capemon_observed``.
    """
    selected = normalize_child_attach_policy(policy)
    if not alive:
        return "target_exited_capemon_observed"
    if selected == "capemon_only":
        return "capemon_only"
    if selected == "immediate":
        return "attach_now"
    if float(elapsed) < max(0.0, float(exclusive_window)):
        return "wait_exclusive_window"
    return "attach_now"


def child_prewarm_decision(
    *,
    require_prewarmed_arch: bool,
    prewarm_enabled: bool,
    target_arch: str | None,
    requested_arches: object,
    usable_arches: object,
) -> str:
    """Decide whether an adaptive child attach is safe to attempt.

    Only architectures explicitly requested for injector prewarming are gated.
    An unknown or native architecture is therefore not blocked accidentally.
    If a requested target architecture failed prewarm, CAPEMON/Sysmon retains
    ownership rather than starting a slow cold attach in a short-lived child.
    """
    if not require_prewarmed_arch or not prewarm_enabled:
        return "attach_allowed"
    arch = str(target_arch or "").strip().lower()
    requested = {
        str(item).strip().lower() for item in (requested_arches or [])
        if str(item).strip()
    }
    usable = {
        str(item).strip().lower() for item in (usable_arches or [])
        if str(item).strip()
    }
    if not arch or arch not in requested:
        return "attach_allowed"
    if arch in usable:
        return "attach_allowed"
    return "capemon_only_prewarm_unavailable"
