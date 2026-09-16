"""Live service correlation for the sandbox controller, with bounded observation.

Only service binaries proven by current-run Security 4697 and Sysmon identities
are enrolled. The SCM process itself is never enrolled as a malware descendant.
"""
import logging
import os
import threading
import time

import psutil

from lib.common.service_graph import correlate, path_key, stamp
from lib.common.sysmon_bridge import SysmonRealtimeBridge

log = logging.getLogger(__name__)
CRITICAL_NAMES = {'system', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
                  'winlogon.exe', 'services.exe', 'lsass.exe'}


class ServiceTrackingMixin:
    def _init_service_tracking(self):
        self.service_tracking_enabled = self._as_bool(self.options.get('frida_service_tracking', True))
        self.service_capemon_enabled = self._as_bool(self.options.get('frida_service_capemon', True))
        self.service_events = []
        self.service_events_dropped = 0
        self.service_bridges = {}
        self.service_bridge_ever_active = set()
        self.service_graph = {}
        self._service_revision = 0
        self._service_reconciled = None
        self._service_reconcile_lock = threading.Lock()
        self._service_pending_since = None

    def _start_service_tracking(self):
        if not self.service_tracking_enabled or not self.sysmon_bridge_enabled:
            return
        for channel, ids in [('Security', (4697,)), ('System', (7045, 7009, 7000, 7030, 7036, 7031, 7034))]:
            bridge = SysmonRealtimeBridge(on_event=self._handle_service_event,
                                         event_ids=ids, channel=channel, logger=log)
            self.service_bridges[channel] = bridge
            bridge.start()
            if bridge.wait_until_active(timeout=1.0):
                self.service_bridge_ever_active.add(channel)
        log.info('[P32320] Service correlation subscriptions: %s', sorted(self.service_bridge_ever_active))

    def _handle_service_event(self, event):
        provider = event.get('provider')
        if not ((provider == 'Microsoft-Windows-Security-Auditing' and event.get('event_id') == 4697)
                or (provider == 'Service Control Manager' and event.get('event_id') in {7045, 7009, 7000, 7030, 7036, 7031, 7034})):
            return
        at = stamp(event.get('utc_time'))
        if at is None or at < self.started_wall or at > time.time() + 2:
            return
        with self.session_lock:
            self.service_bridge_ever_active.add('Security' if event['event_id'] == 4697 else 'System')
            if len(self.service_events) >= 5000:
                self.service_events_dropped += 1
                return
            self.service_events.append(dict(event))
            self._service_revision += 1

    def _reconcile_service_lineage(self):
        if not self.service_tracking_enabled or not self.target_pid:
            return
        if not self._service_reconcile_lock.acquire(blocking=False):
            return
        try:
            with self.session_lock:
                revision = (self._service_revision, len(self.sysmon_process_events), self.target_pid)
                if revision == self._service_reconciled:
                    return
                runtime = {'run_id': self.run_id, 'run_started_wall': self.started_wall,
                           'run_stopped_wall': self.stopped_wall or time.time(),
                           'target_pid': self.target_pid,
                           'lineage': {p: dict(m) for p, m in self.lineage.items()}}
                events = list(self.sysmon_process_events) + list(self.service_events)
                # EID1 may arrive just before root discovery; recover its identity
                # only when the already selected PID, creation time and image agree.
                for p, meta in runtime['lineage'].items():
                    if meta.get('sysmon_guid'):
                        continue
                    candidates = [e for e in events if e.get('provider') == 'Microsoft-Windows-Sysmon'
                                  and e.get('event_id') == 1
                                  and str(e.get('data', {}).get('ProcessId')) == str(p)
                                  and path_key(e['data'].get('Image')) == path_key(meta.get('exe'))
                                  and stamp(e.get('utc_time')) is not None
                                  and abs(stamp(e['utc_time']) - (meta.get('create_time') or 0)) < 0.5]
                    if len(candidates) == 1:
                        meta['sysmon_guid'] = str(candidates[0]['data'].get('ProcessGuid') or '').strip('{}').upper()
                        self.lineage[p]['sysmon_guid'] = meta['sysmon_guid']
            graph = correlate({}, runtime, events, [])
            self.service_graph = graph
            self._service_reconciled = revision
            if graph['unresolved_services'] and self._service_pending_since is None:
                self._service_pending_since = time.monotonic()
            elif not graph['unresolved_services']:
                self._service_pending_since = None
            if self.stop_event.is_set():
                return
            for link in graph['links']:
                self._enroll_service_link(link)
        finally:
            self._service_reconcile_lock.release()

    def _enroll_service_link(self, link):
        pid = link['process_id']; guid = link['process_guid']
        created = stamp(link['process_created_utc'])
        with self.session_lock:
            previous = self.lineage.get(pid)
            if previous and str(previous.get('sysmon_guid') or '').strip('{}').upper() == guid:
                return
            if previous and self._identity_still_alive(pid, previous.get('create_time')):
                self._emit_evidence('service_identity_conflict', pid=pid, process_guid=guid)
                return
        # Keep exited instances as evidence. Only a matching live instance may be instrumented.
        alive = False
        try:
            proc = psutil.Process(pid)
            observed_ctime = proc.create_time()
            alive = proc.is_running() and abs(observed_ctime - created) < 0.5 and path_key(proc.exe()) == path_key(link['image'])
            if alive:
                created = observed_ctime
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            pass
        identity = (pid, round(created, 3))
        name = link['image'].replace('/', '\\').rsplit('\\', 1)[-1].lower()
        with self.session_lock:
            self.lineage[pid] = {'create_time': created, 'ppid': link['parent_pid'],
                                 'exe': link['image'], 'role': link['role'],
                                 'sysmon_guid': guid, 'sysmon_image': link['image'],
                                 'service_name': link['service_name'], 'creator_pid': link['creator_pid'],
                                 'service_evidence': link['evidence'],
                                 'observed_monotonic': time.monotonic(),
                                 'capemon_request': 'not_requested',
                                 'lifetime_observation': 'live_identity_verified' if alive else 'event_only'}
            self._emit_evidence('service_process_enrolled', pid=pid, process_guid=guid,
                                parent_pid=link['parent_pid'], creator_pid=link['creator_pid'],
                                service_name=link['service_name'], role=link['role'], alive=alive)
            if not alive or name in CRITICAL_NAMES or name in self.child_exclude_names:
                return
            if len(self.sessions) + len(self.pending_identities) >= self.max_sessions:
                self.lineage[pid]['capemon_request'] = 'session_limit'
                return
            if identity in self.pending_identities or self.stop_event.is_set():
                return
            self.pending_identities.add(identity)
        worker = threading.Thread(target=self._instrument_service_worker,
                                  args=(pid, created, link['image'], identity),
                                  name=f'P32320-service-{pid}', daemon=True)
        self.child_threads.append(worker)
        worker.start()

    def _instrument_service_worker(self, pid, created, image, identity):
        try:
            if self.stop_event.is_set() or not self._identity_still_alive(pid, created):
                return
            monitor_mapped = False
            try:
                dll_dir = path_key(os.path.join(os.getcwd(), 'dll')) + '\\'
                monitor_mapped = any(path_key(getattr(m, 'path', '')).startswith(dll_dir)
                                     and str(getattr(m, 'path', '')).lower().endswith('.dll')
                                     for m in psutil.Process(pid).memory_maps(grouped=False))
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                pass
            if self.service_capemon_enabled and not monitor_mapped and not self._capemon_ready_signal(pid):
                from lib.api.process import Process
                request = Process(options=self.options, config=self.config, pid=pid)
                try:
                    accepted = request.inject(interest=image, nosleepskip=True, loader_timeout=10.0)
                    with self.session_lock:
                        self.lineage[pid]['capemon_request'] = 'loader_accepted' if accepted else 'failed'
                    self._emit_evidence('service_monitor_request', pid=pid, accepted=bool(accepted),
                                        interpretation='Loader acceptance is not proof of API coverage.')
                except Exception as exc:
                    with self.session_lock:
                        self.lineage[pid]['capemon_request'] = 'failed'
                    self._emit_evidence('service_monitor_error', pid=pid, error=type(exc).__name__)
                finally:
                    request.close()
            self._instrument_process(pid, created, image, identity, role='child')
        except Exception as exc:
            with self.session_lock:
                if pid in self.lineage:
                    self.lineage[pid]['capemon_request'] = 'failed'
            self._emit_evidence('service_monitor_error', pid=pid, error=type(exc).__name__)
        finally:
            with self.session_lock:
                self.pending_identities.discard(identity)

    def has_live_related_processes(self):
        """Used only to defer early completion; the analyzer's hard timeout still applies."""
        if not self.service_tracking_enabled or self.stop_event.is_set():
            return False
        self._reconcile_service_lineage()
        with self.session_lock:
            related = [(p, dict(m)) for p, m in self.lineage.items()
                       if m.get('role') in {'service_process', 'service_descendant'}]
        for pid, meta in related:
            if meta.get('lifetime_observation') == 'live_identity_verified' and self._identity_still_alive(pid, meta['create_time']):
                return True
        return self._service_pending_since is not None and time.monotonic() - self._service_pending_since < 5.0

    def _stop_service_tracking(self):
        for channel, bridge in self.service_bridges.items():
            if bridge.active:
                self.service_bridge_ever_active.add(channel)
            bridge.drain(timeout=1.0, quiet_period=0.2)
            bridge.stop()
        self._reconcile_service_lineage()

    def _service_tracking_summary(self):
        return {'enabled': self.service_tracking_enabled, 'revision': 'p32320',
                'security_ever_active': 'Security' in self.service_bridge_ever_active,
                'system_ever_active': 'System' in self.service_bridge_ever_active,
                'events': list(self.service_events),
                'events_dropped': self.service_events_dropped + sum(b.dropped for b in self.service_bridges.values()),
                'subscriptions': {k: {'ever_active': k in self.service_bridge_ever_active,
                                      'error': b.last_error} for k, b in self.service_bridges.items()},
                'links': self.service_graph.get('links', [])}
