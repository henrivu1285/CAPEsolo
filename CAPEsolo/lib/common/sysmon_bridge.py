import ctypes
import logging
import os
import queue
import threading
import time
import xml.etree.ElementTree as ET

log = logging.getLogger(__name__)

_EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_NS = {"e": _EVENT_NS}


def _strip_braces(value):
    value = str(value or "").strip()
    return value.strip("{}").upper() if value else ""


def parse_sysmon_event_xml(xml_text):
    """Parse the small subset of Sysmon XML needed by FridaMuncher P3 (P2.1 Hybrid sensor set).

    Returns a normalized dict or None when the event is malformed / unsupported.
    This parser is intentionally independent from the Windows API so it can be
    unit-tested off-guest.
    """
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return None

    system = root.find("e:System", _NS)
    if system is None:
        return None

    def sys_text(tag):
        node = system.find(f"e:{tag}", _NS)
        return (node.text or "").strip() if node is not None else ""

    try:
        event_id = int(sys_text("EventID"))
    except Exception:
        return None

    event = {
        "event_id": event_id,
        "record_id": None,
        "utc_time": "",
        "provider": "",
        "computer": sys_text("Computer"),
        "channel": sys_text("Channel"),
        "data": {},
    }

    try:
        event["record_id"] = int(sys_text("EventRecordID"))
    except Exception:
        pass

    provider = system.find("e:Provider", _NS)
    if provider is not None:
        event["provider"] = str(provider.attrib.get("Name") or "")

    time_node = system.find("e:TimeCreated", _NS)
    if time_node is not None:
        event["utc_time"] = str(time_node.attrib.get("SystemTime") or "")

    event_data = root.find("e:EventData", _NS)
    if event_data is not None:
        for node in event_data.findall("e:Data", _NS):
            name = str(node.attrib.get("Name") or "")
            if name:
                event["data"][name] = (node.text or "").strip()

    # Convenience aliases for the process/injection and network event families
    # consumed by P3.2.3.14. Keep the original EventData dict as raw evidence.
    d = event["data"]
    if event_id == 1:  # ProcessCreate
        event.update(
            process_guid=_strip_braces(d.get("ProcessGuid")),
            process_id=_to_int(d.get("ProcessId")),
            image=d.get("Image", ""),
            parent_process_guid=_strip_braces(d.get("ParentProcessGuid")),
            parent_process_id=_to_int(d.get("ParentProcessId")),
            parent_image=d.get("ParentImage", ""),
            command_line=d.get("CommandLine", ""),
        )
    elif event_id == 5:  # ProcessTerminate
        event.update(
            process_guid=_strip_braces(d.get("ProcessGuid")),
            process_id=_to_int(d.get("ProcessId")),
            image=d.get("Image", ""),
        )
    elif event_id == 3:  # NetworkConnect
        event.update(
            process_guid=_strip_braces(d.get("ProcessGuid")),
            process_id=_to_int(d.get("ProcessId")),
            image=d.get("Image", ""),
            user=d.get("User", ""),
            protocol=str(d.get("Protocol", "")).lower(),
            initiated=str(d.get("Initiated", "")).lower() in {"true", "1", "yes"},
            source_is_ipv6=str(d.get("SourceIsIpv6", "")).lower() in {"true", "1", "yes"},
            source_ip=d.get("SourceIp", ""),
            source_hostname=d.get("SourceHostname", ""),
            source_port=_to_int(d.get("SourcePort")),
            source_port_name=d.get("SourcePortName", ""),
            destination_is_ipv6=str(d.get("DestinationIsIpv6", "")).lower() in {"true", "1", "yes"},
            destination_ip=d.get("DestinationIp", ""),
            destination_hostname=d.get("DestinationHostname", ""),
            destination_port=_to_int(d.get("DestinationPort")),
            destination_port_name=d.get("DestinationPortName", ""),
        )
    elif event_id == 8:  # CreateRemoteThread
        event.update(
            source_process_guid=_strip_braces(d.get("SourceProcessGuid")),
            source_process_id=_to_int(d.get("SourceProcessId")),
            source_image=d.get("SourceImage", ""),
            target_process_id=_to_int(d.get("TargetProcessId")),
            target_image=d.get("TargetImage", ""),
            new_thread_id=_to_int(d.get("NewThreadId")),
            start_address=d.get("StartAddress", ""),
            start_module=d.get("StartModule", ""),
            start_function=d.get("StartFunction", ""),
        )
    elif event_id == 25:  # ProcessTampering
        event.update(
            process_guid=_strip_braces(d.get("ProcessGuid")),
            process_id=_to_int(d.get("ProcessId")),
            image=d.get("Image", ""),
            tamper_type=d.get("Type", d.get("EventType", "")),
        )
    elif event_id == 22:  # DNSQuery
        event.update(
            process_guid=_strip_braces(d.get("ProcessGuid")),
            process_id=_to_int(d.get("ProcessId")),
            image=d.get("Image", ""),
            user=d.get("User", ""),
            query_name=d.get("QueryName", ""),
            query_status=d.get("QueryStatus", ""),
            query_results=d.get("QueryResults", ""),
        )

    return event


def _to_int(value):
    try:
        return int(str(value or "0"), 0)
    except Exception:
        try:
            return int(str(value or "0"))
        except Exception:
            return 0


class SysmonRealtimeBridge:
    """Subscribe to Sysmon/Operational and forward normalized events in real time.

    Uses the native Windows Event Log API (EvtSubscribe + EvtRender) directly via
    ctypes. No polling process is spawned, so the bridge does not generate a
    recurring wevtutil.exe/PowerShell process-creation footprint in the sandbox.

    The bridge is deliberately read-only: it never installs Sysmon, edits its
    configuration, clears logs, or changes CAPEsolo's existing Sysmon auxiliary.
    """

    CHANNEL = "Microsoft-Windows-Sysmon/Operational"

    def __init__(
        self,
        on_event,
        event_ids=(1, 3, 5, 8, 22, 25),
        channel=CHANNEL,
        logger=None,
        queue_size=2048,
        startup_retry_seconds=12.0,
        retry_interval=0.75,
    ):
        self.on_event = on_event
        self.event_ids = tuple(sorted({int(x) for x in event_ids}))
        self.channel = str(channel or self.CHANNEL)
        self.log = logger or log
        self.queue = queue.Queue(maxsize=max(64, int(queue_size)))

        self.stop_event = threading.Event()
        self.worker = None
        self.subscription = None
        self.callback_ref = None
        self.wevtapi = None
        self.active_event = threading.Event()
        self.last_error = None
        self.dropped = 0
        self.startup_retry_seconds = max(0.0, float(startup_retry_seconds))
        self.retry_interval = max(0.1, float(retry_interval))
        self.stats_lock = threading.Lock()
        self.enqueued = 0
        self.processed = 0
        self.last_enqueued_monotonic = 0.0
        self.last_processed_monotonic = 0.0

    @property
    def active(self):
        return self.active_event.is_set() and bool(self.subscription)

    def wait_until_active(self, timeout=0.0):
        return self.active_event.wait(max(0.0, float(timeout)))

    def start(self):
        if os.name != "nt":
            self.last_error = "Windows Event Log API is only available on Windows"
            self.log.warning("[SysmonBridge] %s", self.last_error)
            return False

        if self.worker is not None and self.worker.is_alive():
            return self.active

        self.stop_event.clear()
        self.worker = threading.Thread(
            target=self._run,
            name="FridaMuncher-SysmonBridge",
            daemon=True,
        )
        self.worker.start()
        return True

    def stop(self):
        self.stop_event.set()
        sub = self.subscription
        self.subscription = None
        self.active_event.clear()

        if sub and self.wevtapi is not None:
            try:
                self.wevtapi.EvtClose(sub)
            except Exception:
                pass

        try:
            self.queue.put_nowait(None)
        except Exception:
            pass

        if self.worker is not None and self.worker.is_alive():
            self.worker.join(timeout=2.0)
        return True

    def stats(self):
        with self.stats_lock:
            return {
                "active": self.active,
                "enqueued": int(self.enqueued),
                "processed": int(self.processed),
                "pending": max(0, int(self.enqueued) - int(self.processed)),
                "dropped": int(self.dropped),
                "last_enqueued_monotonic": float(self.last_enqueued_monotonic),
                "last_processed_monotonic": float(self.last_processed_monotonic),
            }

    def drain(self, timeout=2.0, quiet_period=0.5):
        """Wait for late Event Log callbacks and consume the queue before stop.

        EvtSubscribe is asynchronous: the network packet can already be in the
        external PCAP while its EID 3 callback is still pending. A bounded quiet
        window preserves those tail events without keeping analysis shutdown
        open indefinitely.
        """
        timeout = max(0.0, float(timeout))
        quiet_period = max(0.05, min(float(quiet_period), timeout or 0.05))
        started = time.monotonic()
        deadline = started + timeout
        previous = None
        stable_since = started
        while True:
            snapshot = self.stats()
            current = (snapshot["enqueued"], snapshot["processed"], snapshot["dropped"])
            now = time.monotonic()
            if current != previous:
                previous = current
                stable_since = now
            if snapshot["pending"] == 0 and now - stable_since >= quiet_period:
                snapshot.update(
                    status="drained",
                    duration_ms=round((now - started) * 1000.0, 3),
                    quiet_period_ms=round(quiet_period * 1000.0, 3),
                )
                return snapshot
            if now >= deadline:
                snapshot.update(
                    status="timeout" if snapshot["pending"] else "quiet_timeout",
                    duration_ms=round((now - started) * 1000.0, 3),
                    quiet_period_ms=round(quiet_period * 1000.0, 3),
                )
                return snapshot
            time.sleep(min(0.05, max(0.0, deadline - now)))

    def _run(self):
        try:
            self._init_api()
            deadline = __import__("time").monotonic() + self.startup_retry_seconds
            attempts = 0
            while not self.stop_event.is_set():
                attempts += 1
                if self._subscribe(log_failure=False):
                    break
                if __import__("time").monotonic() >= deadline:
                    self.log.warning(
                        "[SysmonBridge] subscription unavailable after %d attempt(s): %s",
                        attempts,
                        self.last_error or "unknown error",
                    )
                    return
                self.stop_event.wait(self.retry_interval)

            if not self.subscription:
                return

            self.log.info(
                "[SysmonBridge] realtime subscription active: channel=%s event_ids=%s",
                self.channel,
                self.event_ids,
            )

            while True:
                try:
                    item = self.queue.get(timeout=0.25)
                except queue.Empty:
                    if self.stop_event.is_set():
                        break
                    continue

                if item is None:
                    break

                try:
                    event = parse_sysmon_event_xml(item)
                    if event is not None and event.get("event_id") in self.event_ids:
                        self.on_event(event)
                except Exception:
                    self.log.debug(
                        "[SysmonBridge] event callback processing failed",
                        exc_info=True,
                    )
                finally:
                    with self.stats_lock:
                        self.processed += 1
                        self.last_processed_monotonic = time.monotonic()
        except Exception as exc:
            self.last_error = str(exc)
            self.log.warning("[SysmonBridge] unavailable: %s", exc)
        finally:
            self.active_event.clear()
            sub = self.subscription
            self.subscription = None
            if sub and self.wevtapi is not None:
                try:
                    self.wevtapi.EvtClose(sub)
                except Exception:
                    pass

    def _init_api(self):
        WinDLL = getattr(ctypes, "WinDLL")
        WINFUNCTYPE = getattr(ctypes, "WINFUNCTYPE")
        from ctypes import wintypes

        self._wintypes = wintypes
        self.wevtapi = WinDLL("wevtapi.dll", use_last_error=True)

        # EVT_SUBSCRIBE_CALLBACK: DWORD CALLBACK(Action, Context, Event)
        self._callback_type = WINFUNCTYPE(
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.HANDLE,
        )

        self.wevtapi.EvtSubscribe.argtypes = [
            wintypes.HANDLE,     # Session
            wintypes.HANDLE,     # SignalEvent
            wintypes.LPCWSTR,    # ChannelPath
            wintypes.LPCWSTR,    # Query
            wintypes.HANDLE,     # Bookmark
            ctypes.c_void_p,     # Context
            self._callback_type, # Callback
            wintypes.DWORD,      # Flags
        ]
        self.wevtapi.EvtSubscribe.restype = wintypes.HANDLE

        self.wevtapi.EvtRender.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.wevtapi.EvtRender.restype = wintypes.BOOL

        self.wevtapi.EvtClose.argtypes = [wintypes.HANDLE]
        self.wevtapi.EvtClose.restype = wintypes.BOOL

    def _subscribe(self, log_failure=True):
        # XPath accepted by EvtSubscribe for one Operational channel.
        event_clause = " or ".join(f"EventID={x}" for x in self.event_ids)
        query_text = f"*[System[({event_clause})]]"

        @self._callback_type
        def callback(action, _context, event_handle):
            # EvtSubscribeActionError=0, EvtSubscribeActionDeliver=1.
            if int(action) == 0:
                try:
                    code = int(ctypes.cast(event_handle, ctypes.c_void_p).value or 0)
                except Exception:
                    code = 0
                self.last_error = f"subscription callback error={code}"
                self.log.warning("[SysmonBridge] %s", self.last_error)
                return 0

            xml_text = self._render_event_xml(event_handle)
            if xml_text:
                try:
                    self.queue.put_nowait(xml_text)
                    with self.stats_lock:
                        self.enqueued += 1
                        self.last_enqueued_monotonic = time.monotonic()
                except queue.Full:
                    with self.stats_lock:
                        self.dropped += 1
                    if self.dropped in {1, 10, 100, 1000}:
                        self.log.warning(
                            "[SysmonBridge] event queue full; dropped=%d",
                            self.dropped,
                        )
            return 0

        self.callback_ref = callback  # keep CFUNCTYPE alive for subscription life
        EvtSubscribeToFutureEvents = 1
        sub = self.wevtapi.EvtSubscribe(
            None,
            None,
            self.channel,
            query_text,
            None,
            None,
            self.callback_ref,
            EvtSubscribeToFutureEvents,
        )
        if not sub:
            code = ctypes.get_last_error()
            self.last_error = f"EvtSubscribe failed with Win32 error {code}"
            if log_failure:
                self.log.warning("[SysmonBridge] %s", self.last_error)
            return False

        self.subscription = sub
        self.active_event.set()
        return True

    def _render_event_xml(self, event_handle):
        # EVT_RENDER_FLAGS::EvtRenderEventXml = 1
        EvtRenderEventXml = 1
        ERROR_INSUFFICIENT_BUFFER = 122
        used = self._wintypes.DWORD(0)
        count = self._wintypes.DWORD(0)

        ctypes.set_last_error(0)
        ok = self.wevtapi.EvtRender(
            None,
            event_handle,
            EvtRenderEventXml,
            0,
            None,
            ctypes.byref(used),
            ctypes.byref(count),
        )
        if ok:
            return ""

        err = ctypes.get_last_error()
        if err != ERROR_INSUFFICIENT_BUFFER or used.value <= 0:
            return ""

        # BufferSize is bytes, while create_unicode_buffer expects wchar count.
        wchar_size = ctypes.sizeof(ctypes.c_wchar)
        chars = max(1, (used.value + wchar_size - 1) // wchar_size)
        buffer = ctypes.create_unicode_buffer(chars)

        ctypes.set_last_error(0)
        if not self.wevtapi.EvtRender(
            None,
            event_handle,
            EvtRenderEventXml,
            used.value,
            ctypes.cast(buffer, ctypes.c_void_p),
            ctypes.byref(used),
            ctypes.byref(count),
        ):
            return ""

        return buffer.value
