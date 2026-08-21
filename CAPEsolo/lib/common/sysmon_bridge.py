import ctypes
import logging
import os
import queue
import threading
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

    # Convenience aliases for the four event families consumed by P2.1.
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
        event_ids=(1, 5, 8, 25),
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

            while not self.stop_event.is_set():
                try:
                    item = self.queue.get(timeout=0.25)
                except queue.Empty:
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
                except queue.Full:
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
