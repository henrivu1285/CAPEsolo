"""Build the results["network"] summary CAPEsolo's signatures and reports expect.

Nothing populated this key before, so the 14 network signatures that ship in
signatures/community were loaded and evaluated on every run but could never match, and
neither report had a network section.

Three sources feed it, matching what CAPEv2 merges in modules/processing/network.py
(_merge_behavior_network and _merge_js_log_network alongside the pcap):

  * the behaviour log - capemon records the network and socket API calls, so hosts, DNS
    lookups and HTTP requests are known even with no capture at all;
  * the JS console log - the interceptor reports fetch/XHR requests and DNS lookups that
    never reach a hooked Win32 API;
  * a task-scoped capture fetched from the Ubuntu/INetSim VM, or a capture
    selected manually in the Network tab.

The key shapes are CAPEv2's, because the signatures read them directly: hosts entries need
"ip", domains "domain", http "uri", dns "request" and "answers" (each with "data"), udp
"dst"/"dport", icmp "dst"/"type", smtp "dst".
"""

import logging
from urllib.parse import urlparse

log = logging.getLogger(__name__)

# Behaviour-log APIs worth reading, grouped by what they tell us. Argument names come from
# logtbl.py, which is what the parsed calls are labelled with.
DNS_APIS = {
    "DnsQuery_A": "Name",
    "DnsQuery_UTF8": "Name",
    "DnsQuery_W": "Name",
    "getaddrinfo": "NodeName",
    "GetAddrInfoW": "NodeName",
    "gethostbyname": "Name",
}

URL_APIS = {
    "URLDownloadToFileW": "URL",
    "URLDownloadToFileA": "URL",
    "InternetOpenUrlA": "URL",
    "InternetOpenUrlW": "URL",
    "WinHttpOpenRequest": "ObjectName",
}

# InternetConnect names the host and port directly, which is the one place the behaviour log
# gives a host/port pair without a URL to parse.
CONNECT_APIS = {
    "InternetConnectA": ("ServerName", "ServerPort"),
    "InternetConnectW": ("ServerName", "ServerPort"),
}

# HttpOpenRequest carries only the path; the host came from the earlier InternetConnect on
# the same handle, which is not tracked here, so these contribute a path-only request.
PATH_APIS = {
    "HttpOpenRequestA": "Path",
    "HttpOpenRequestW": "Path",
}


def _EmptyNetwork():
    return {
        "hosts": [],
        "domains": [],
        "tcp": [],
        "udp": [],
        "icmp": [],
        "http": [],
        "http_responses": [],
        "dns": [],
        "smtp": [],
        "irc": [],
        "dead_hosts": [],
        "tls": [],
        "sorted": {"tcp": [], "udp": []},
        # Which sources actually contributed, so a report can say why a section is thin.
        "sources": [],
    }


OS_BACKGROUND_DOMAINS = {
    "dns.msftncsi.com",
    "events.data.microsoft.com",
    "ctldl.windowsupdate.com",
    "fs.microsoft.com",
    "www.msftconnecttest.com",
    "www.msftncsi.com",
}
OS_BACKGROUND_DOMAIN_SUFFIXES = (
    ".events.data.microsoft.com",
    ".windowsupdate.com",
)
ANALYST_APPLICATION_DOMAINS = {
    "main.vscode-cdn.net",
    "update.code.visualstudio.com",
}


def _TrafficClassification(
    attribution=None, host="", protocol="", src="", sport=0, dst="", dport=0
):
    """Classify provenance without deleting any wire evidence.

    Unknown traffic stays signature-eligible. A flow is suppressed from
    malware signatures only when tracked lineage or a well-known lab/OS source
    gives positive evidence that it is environmental.
    """
    attr = attribution if isinstance(attribution, dict) else {}
    process = str(attr.get("process") or "").replace("/", "\\").lower()
    domain = str(host or "").split(":", 1)[0].rstrip(".").lower()
    if attr.get("tracked"):
        return "tracked_malware", True, "tracked_analysis_lineage"
    try:
        sport, dport = int(sport or 0), int(dport or 0)
    except (TypeError, ValueError):
        sport, dport = 0, 0
    endpoint = str(dst or host or "").strip("[]").lower()
    discovery = {
        ("224.0.0.251", 5353, "udp", "mdns_multicast"),
        ("ff02::fb", 5353, "udp", "mdns_multicast"),
        ("224.0.0.252", 5355, "udp", "llmnr_multicast"),
        ("ff02::1:3", 5355, "udp", "llmnr_multicast"),
        ("239.255.255.250", 1900, "udp", "ssdp_multicast"),
        ("ff02::c", 1900, "udp", "ssdp_multicast"),
    }
    for address, port, transport, reason in discovery:
        if endpoint == address and dport == port and str(protocol).lower() == transport:
            return "local_service_discovery", False, reason
    if domain in OS_BACKGROUND_DOMAINS or any(
        domain.endswith(suffix) for suffix in OS_BACKGROUND_DOMAIN_SUFFIXES
    ):
        reason = (
            "known_microsoft_telemetry"
            if domain == "events.data.microsoft.com"
            or domain.endswith(".events.data.microsoft.com")
            else "known_windows_connectivity_probe"
        )
        return "os_background", False, reason
    if domain in ANALYST_APPLICATION_DOMAINS or process.endswith("\\code.exe"):
        return "analyst_application", False, "known_analyst_application"
    if process.endswith(("\\svchost.exe", "\\system", "\\services.exe")):
        return "os_background", False, "untracked_windows_service"
    if attr.get("status") == "mapped" and not attr.get("tracked"):
        return "untracked_process", False, "mapped_outside_analysis_lineage"
    return "unattributed", True, "no_positive_environmental_attribution"


def InterpretNetworkAbsence(
    capture_status, frames, packets, total_flows, mapped_flows, tracked_flows,
    clock_correlation=None,
):
    """Describe what network absence means without turning gaps into negatives."""
    clock = clock_correlation if isinstance(clock_correlation, dict) else {}
    clock_status = str(clock.get("status") or "unavailable")
    if capture_status not in {"complete", "empty"}:
        return "network_coverage_unavailable"
    if capture_status == "empty" or (int(frames or 0) == 0 and int(packets or 0) == 0):
        return "network_not_observed_capture_empty"
    if clock_status == "clock_discontinuity" or (
        clock.get("discontinuity_detected") and not clock.get("usable")
    ):
        return "network_attribution_inconclusive_clock_discontinuity"
    if int(tracked_flows or 0) > 0:
        return "tracked_network_observed"
    if clock_status == "clock_segmented" and int(mapped_flows or 0) < int(total_flows or 0):
        return "network_attribution_partial_clock_segments"
    if not clock.get("usable") and int(total_flows or 0):
        return "network_attribution_inconclusive_clock_unsynchronized"
    if int(total_flows or 0) and int(mapped_flows or 0) == int(total_flows or 0):
        return "tracked_network_not_observed_after_complete_attribution"
    if int(mapped_flows or 0) > 0:
        return "tracked_network_not_observed_with_partial_attribution"
    if int(total_flows or 0):
        return "network_attribution_inconclusive_no_pid_matches"
    return "network_not_observed_with_capture"


def _Argument(call, name):
    """Read one argument value from a parsed behaviour call."""
    for argument in call.get("arguments") or ():
        if argument.get("name") == name:
            value = argument.get("value")
            if value is None:
                return ""
            return str(value)

    return ""


def _IsIpv4(value):
    parts = value.split(".")
    if len(parts) != 4:
        return False

    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False

    return True


class _Collector:
    """Accumulates the summary, keeping each list deduplicated as it grows."""

    def __init__(self):
        self.network = _EmptyNetwork()
        self._hosts = set()
        self._domains = set()
        self._requests = {}
        self._dns = {}

    def AddHost(self, ip):
        if not ip or not _IsIpv4(ip) or ip in self._hosts:
            return

        self._hosts.add(ip)
        # Stable CAPEv2-compatible keys keep legacy signatures from raising
        # KeyError when GeoIP/reverse DNS enrichment is unavailable.
        self.network["hosts"].append({
            "ip": ip,
            "hostname": "",
            "country_name": "",
            "country_code": "",
            "asn": None,
        })

    def AddDomain(self, domain, ip=""):
        if not domain:
            return
        if domain not in self._domains:
            self._domains.add(domain)
            self.network["domains"].append({"domain": domain, "ip": ip})
        elif ip:
            for entry in self.network["domains"]:
                if entry.get("domain") == domain and not entry.get("ip"):
                    entry["ip"] = ip
                    break
        if ip and _IsIpv4(ip):
            self.AddHost(ip)
            for entry in self.network["hosts"]:
                if entry.get("ip") == ip and not entry.get("hostname"):
                    entry["hostname"] = domain
                    break

    def AddDnsRequest(
        self, name, answers=None, rtype="A", occurrence=True,
        attribution=None, timestamp=0.0,
    ):
        """Keep one row per name while counting every raw query occurrence."""
        if not name:
            return

        entry = self._dns.get(name)
        if entry is None:
            traffic_class, eligible, reason = _TrafficClassification(None, name)
            entry = {
                "request": name,
                "type": rtype,
                "answers": [],
                "count": 0,
                "response_count": 0,
                "first_seen": timestamp or 0.0,
                "last_seen": timestamp or 0.0,
                "requester_attributions": [],
                "traffic_class": traffic_class,
                "signature_eligible": eligible,
                "classification_reason": reason,
            }
            self._dns[name] = entry
            self.network["dns"].append(entry)

        if occurrence:
            entry["count"] = int(entry.get("count") or 0) + 1
            if timestamp:
                entry["first_seen"] = entry.get("first_seen") or timestamp
                entry["last_seen"] = timestamp
        else:
            entry["response_count"] = int(entry.get("response_count") or 0) + 1

        attr = attribution if isinstance(attribution, dict) else {}
        if attr:
            requesters = entry.setdefault("requester_attributions", [])
            identity = (attr.get("pid"), attr.get("process_guid"), attr.get("status"))
            known = {
                (item.get("pid"), item.get("process_guid"), item.get("status"))
                for item in requesters if isinstance(item, dict)
            }
            if identity not in known:
                requesters.append(attr)
            if attr.get("tracked") or not entry.get("attribution"):
                entry["attribution"] = attr
                traffic_class, eligible, reason = _TrafficClassification(attr, name)
                entry["traffic_class"] = traffic_class
                entry["signature_eligible"] = eligible
                entry["classification_reason"] = reason

        seen = {(a["data"], a["type"]) for a in entry["answers"]}
        for address in answers or ():
            if not address or (address, "A") in seen:
                continue
            entry["answers"].append({"data": address, "type": "A"})
            seen.add((address, "A"))
            self.AddHost(address)
            self.AddDomain(name, address)

        if not answers:
            self.AddDomain(name)

    def AddHttp(self, url="", method="GET", host="", path="", data="", **metadata):
        """Add or enrich one HTTP request without double-counting decrypted views."""
        uri = url
        try:
            port = int(metadata.get("dport") or 80)
        except (TypeError, ValueError):
            port = 80
        if url:
            try:
                parsed = urlparse(url)
            except ValueError:
                parsed = None

            if parsed and parsed.scheme in ("http", "https"):
                host = host or parsed.hostname or ""
                path = parsed.path or "/"
                if parsed.query:
                    path = f"{path}?{parsed.query}"
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not uri:
            path = path or "/"
            if host:
                scheme = "https" if port == 443 else "http"
                authority = host if port in (80, 443) else f"{host}:{port}"
                uri = f"{scheme}://{authority}{path}"
            else:
                uri = path

        attribution = metadata.get("attribution") if isinstance(metadata.get("attribution"), dict) else {}
        traffic_class, signature_eligible, classification_reason = _TrafficClassification(
            attribution, host, "tcp",
            metadata.get("src"), metadata.get("sport"),
            metadata.get("dst"), metadata.get("dport") or port,
        )
        has_socket = all(metadata.get(name) not in (None, "") for name in ("src", "sport", "dst", "dport"))
        if has_socket:
            key = (
                "socket", method, host, uri,
                metadata.get("src"), int(metadata.get("sport")),
                metadata.get("dst"), int(metadata.get("dport")),
            )
        else:
            key = ("logical", method, host, uri, attribution.get("pid"))
        existing = self._requests.get(key)
        occurrence = metadata.get("occurrence", True) is not False
        # Plaintext/decryption processors describe an already captured request.  If an
        # older decoder omitted socket metadata, merge only when the logical identity
        # has exactly one candidate; ambiguity is retained as a separate row.
        if existing is None and not occurrence:
            candidates = [
                request for request in self.network["http"]
                if request.get("method") == method and request.get("host") == host and request.get("uri") == uri
            ]
            if len(candidates) == 1:
                existing = candidates[0]
        if existing is not None:
            if occurrence:
                existing["count"] = int(existing.get("count") or 1) + 1
            if metadata.get("time"):
                existing["last_seen"] = max(float(existing.get("last_seen") or 0.0), float(metadata.get("time")))
            if data and not existing.get("data"):
                existing["data"] = data
            source = str(metadata.get("observation_source") or "capture")
            if source not in existing.setdefault("observation_sources", []):
                existing["observation_sources"].append(source)
            if attribution.get("tracked") and not (existing.get("attribution") or {}).get("tracked"):
                existing["attribution"] = attribution
                existing["traffic_class"] = traffic_class
                existing["signature_eligible"] = signature_eligible
                existing["classification_reason"] = classification_reason
            return

        headers = metadata.get("headers") if isinstance(metadata.get("headers"), dict) else {}
        user_agent = next(
            (value for name, value in headers.items() if str(name).lower() == "user-agent"),
            "",
        )
        if not data and headers:
            data = "\r\n".join(f"{name}: {value}" for name, value in headers.items())
        entry = {
                "count": 1,
                "host": host,
                "port": port,
                "method": method,
                "uri": uri,
                "path": path or uri,
                "data": data,
                "body": "",
                "version": str(metadata.get("version") or "1.1"),
                "user-agent": user_agent,
                "headers": headers,
                "traffic_class": traffic_class,
                "signature_eligible": signature_eligible,
                "classification_reason": classification_reason,
                "first_seen": metadata.get("time") or 0.0,
                "last_seen": metadata.get("time") or 0.0,
                "observation_sources": [str(metadata.get("observation_source") or "capture")],
            }
        for key_name in ("src", "sport", "dst", "dport", "time", "attribution"):
            if key_name in metadata:
                entry[key_name] = metadata[key_name]
        self.network["http"].append(entry)
        self._requests[key] = entry
        if host:
            if _IsIpv4(host):
                self.AddHost(host)
            else:
                self.AddDomain(host)

    def AddHttpResponse(self, status_code="", reason="", version="", **metadata):
        attribution = metadata.get("attribution") if isinstance(metadata.get("attribution"), dict) else {}
        traffic_class, signature_eligible, classification_reason = _TrafficClassification(
            attribution, metadata.get("host") or "", "tcp",
            metadata.get("src"), metadata.get("sport"),
            metadata.get("dst"), metadata.get("dport"),
        )
        self.network["http_responses"].append({
            "src": metadata.get("src") or "",
            "sport": metadata.get("sport") or 0,
            "dst": metadata.get("dst") or "",
            "dport": metadata.get("dport") or 0,
            "time": metadata.get("time") or 0.0,
            "version": version,
            "status_code": status_code,
            "reason": reason,
            "headers": metadata.get("headers") or {},
            "attribution": attribution,
            "traffic_class": traffic_class,
            "signature_eligible": signature_eligible,
            "classification_reason": classification_reason,
        })

    def AddFlow(self, protocol, src, sport, dst, dport, timestamp=0.0, **metadata):
        if protocol not in ("tcp", "udp") or not dst:
            return

        entry = {
            "src": src,
            "sport": sport,
            "dst": dst,
            "dport": dport,
            "offset": 0,
            "time": timestamp,
        }
        traffic_class, signature_eligible, classification_reason = _TrafficClassification(
            metadata.get("attribution"), metadata.get("host") or "",
            protocol, src, sport, dst, dport,
        )
        entry.update(
            traffic_class=traffic_class,
            signature_eligible=signature_eligible,
            classification_reason=classification_reason,
        )
        for key in (
            "flow_id", "last_seen", "packet_count", "payload_bytes", "attribution"
        ):
            if key in metadata:
                entry[key] = metadata[key]
        self.network[protocol].append(entry)
        self.network["sorted"][protocol].append(entry)
        self.AddHost(dst)

    def Source(self, name):
        if name not in self.network["sources"]:
            self.network["sources"].append(name)


def _FromBehavior(collector, behavior):
    """Pull hosts, DNS lookups and HTTP requests out of the monitor's API log."""
    processes = (behavior or {}).get("processes") or []
    found = False
    for process in processes:
        for call in process.get("calls") or ():
            api = call.get("api") or ""
            category = call.get("category") or ""
            if category not in ("network", "socket"):
                continue

            if api in DNS_APIS:
                name = _Argument(call, DNS_APIS[api])
                if name:
                    collector.AddDnsRequest(name)
                    found = True
            elif api in URL_APIS:
                url = _Argument(call, URL_APIS[api])
                if url:
                    collector.AddHttp(url=url)
                    found = True
            elif api in CONNECT_APIS:
                nameArg, portArg = CONNECT_APIS[api]
                host = _Argument(call, nameArg)
                port = _Argument(call, portArg)
                if host:
                    if _IsIpv4(host):
                        collector.AddHost(host)
                    else:
                        collector.AddDomain(host)
                    try:
                        dport = int(port)
                    except (TypeError, ValueError):
                        dport = 0
                    if _IsIpv4(host) and dport:
                        collector.AddFlow("tcp", "", 0, host, dport)
                    found = True
            elif api in PATH_APIS:
                path = _Argument(call, PATH_APIS[api])
                if path:
                    collector.AddHttp(path=path)
                    found = True
            elif api == "bind":
                # A bound listening port is what network_bind looks for.
                found = True

    if found:
        collector.Source("behavior")


def _FromJsLog(collector, jsLog):
    """Pull requests and lookups the JS interceptor saw.

    A script using fetch or XHR goes through the runtime's own stack, so these need not
    appear in the behaviour log at all.
    """
    events = (jsLog or {}).get("events") or []
    found = False
    for event in events:
        name = event.get("event") or ""
        if name == "http_request":
            url = event.get("url") or ""
            if url:
                collector.AddHttp(url=url, method=event.get("method") or "GET")
                found = True
        elif name == "dns_query":
            hostname = event.get("hostname") or ""
            if hostname:
                collector.AddDnsRequest(hostname)
                found = True
        elif name == "dns_result":
            hostname = event.get("hostname") or ""
            addresses = event.get("addresses") or []
            if isinstance(addresses, str):
                addresses = [addresses]
            if hostname:
                collector.AddDnsRequest(hostname, answers=addresses, occurrence=False)
                found = True
        elif name == "tcp_connect":
            host = str(event.get("host") or "")
            try:
                port = int(event.get("port") or 0)
            except (TypeError, ValueError):
                port = 0
            if host:
                if _IsIpv4(host):
                    collector.AddFlow("tcp", "", 0, host, port)
                else:
                    collector.AddDomain(host)
                found = True

    if found:
        collector.Source("js_log")


def _FromCapture(collector, capture):
    """Fold in a parsed capture from capelib.network.NetworkData."""
    if not capture:
        return

    for event in capture.get("events") or ():
        kind = event.get("kind")
        if kind == "DNS":
            # The parsed detail is not carried through, so use what the row exposes: the
            # question, plus any answers the resolver returned.
            host = event.get("host") or ""
            if host:
                dns = event.get("dns") if isinstance(event.get("dns"), dict) else {}
                answers = [
                    item.get("data") for item in (dns.get("answers") or [])
                    if isinstance(item, dict) and item.get("type") in ("A", "AAAA")
                ]
                is_response = bool(dns.get("response"))
                collector.AddDnsRequest(
                    host,
                    answers=answers,
                    rtype=dns.get("query_type") or "A",
                    occurrence=not is_response,
                    attribution=event.get("attribution") if not is_response else None,
                    timestamp=event.get("time") or 0.0,
                )
        elif kind == "HTTP":
            info = event.get("info") or ""
            http = event.get("http") if isinstance(event.get("http"), dict) else {}
            start_line = http.get("start_line") or info
            common = {
                "src": event.get("src_ip") or event.get("src") or "",
                "sport": event.get("src_port") or 0,
                "dst": event.get("dst_ip") or event.get("dst") or "",
                "dport": event.get("dst_port") or 0,
                "time": event.get("time") or 0.0,
                "attribution": event.get("attribution"),
                "headers": http.get("headers") or {},
            }
            if http.get("response"):
                collector.AddHttpResponse(
                    status_code=http.get("status_code") or "",
                    reason=http.get("reason") or "",
                    version=http.get("version") or "",
                    host=http.get("host") or "",
                    **common,
                )
            else:
                collector.AddHttp(
                    path=http.get("target") or (start_line.split(" ")[1] if " " in start_line else "/"),
                    method=http.get("method") or (start_line.split(" ", 1)[0] if start_line else "GET"),
                    version=http.get("version") or "1.1",
                    host=http.get("host") or event.get("host") or event.get("dst") or "",
                    **common,
                )
        elif kind == "TLS":
            host = event.get("host") or ""
            if host:
                collector.AddDomain(host, event.get("dst") or "")
            collector.AddHost(event.get("dst") or "")
            tls = event.get("tls") if isinstance(event.get("tls"), dict) else {}
            attribution = event.get("attribution")
            traffic_class, eligible, reason = _TrafficClassification(
                attribution, host, "tcp",
                event.get("src_ip"), event.get("src_port"),
                event.get("dst_ip"), event.get("dst_port"),
            )
            collector.network["tls"].append({
                    "src": event.get("src_ip") or event.get("src") or "",
                    "sport": event.get("src_port") or 0,
                    "dst": event.get("dst_ip") or event.get("dst") or "",
                    "dport": event.get("dst_port") or 0,
                    "server_name": host,
                    "version": tls.get("version") or "",
                    "hello": tls.get("hello") or "",
                    "has_keys": bool(tls.get("has_keys")),
                    "attribution": attribution,
                    "traffic_class": traffic_class,
                    "signature_eligible": eligible,
                    "classification_reason": reason,
                })

    for ip, names in (capture.get("hosts") or {}).items():
        collector.AddHost(ip)
        for name in names:
            collector.AddDomain(name, ip)

    for flow in capture.get("flows") or ():
        info = flow.get("info") or ""
        protocol = str(flow.get("protocol") or ("udp" if info.startswith("UDP") else "tcp")).lower()
        src = flow.get("src_ip")
        sport = flow.get("src_port")
        dst = flow.get("dst_ip")
        dport = flow.get("dst_port")
        if src is None or dst is None:
            src, _, sport = str(flow.get("src") or "").rpartition(":")
            dst, _, dport = str(flow.get("dst") or "").rpartition(":")
        try:
            collector.AddFlow(
                protocol,
                src,
                int(sport or 0),
                dst,
                int(dport or 0),
                flow.get("first_seen", flow.get("time") or 0.0),
                flow_id=flow.get("flow_id"),
                last_seen=flow.get("last_seen"),
                packet_count=flow.get("packet_count"),
                payload_bytes=flow.get("payload_bytes"),
                attribution=flow.get("attribution"),
                host=flow.get("host") or "",
            )
        except (TypeError, ValueError):
            continue

    collector.Source("pcap")


def NetworkSummary(behavior=None, jsLog=None, capture=None, decrypted=None):
    """Assemble results["network"] from whichever sources are available.

    Every argument is optional: with no capture the summary still covers what the monitor
    and the JS interceptor observed, which is what makes the network signatures work on a
    run where the user never supplied a pcap.
    """
    collector = _Collector()
    try:
        _FromBehavior(collector, behavior)
    except Exception as e:
        log.warning("Could not read network activity from the behaviour log: %s", e)

    try:
        _FromJsLog(collector, jsLog)
    except Exception as e:
        log.warning("Could not read network activity from the JS log: %s", e)

    try:
        _FromCapture(collector, capture)
    except Exception as e:
        log.warning("Could not read network activity from the capture: %s", e)

    network = collector.network
    if capture:
        raw_events = capture.get("events") or []
        protocol_occurrences = {
            "dns_queries": sum(
                1 for item in raw_events
                if item.get("kind") == "DNS"
                and not (item.get("dns") or {}).get("response")
            ),
            "dns_responses": sum(
                1 for item in raw_events
                if item.get("kind") == "DNS"
                and bool((item.get("dns") or {}).get("response"))
            ),
            "http_requests": sum(
                1 for item in raw_events
                if item.get("kind") == "HTTP"
                and not (item.get("http") or {}).get("response")
            ),
            "http_responses": sum(
                1 for item in raw_events
                if item.get("kind") == "HTTP"
                and bool((item.get("http") or {}).get("response"))
            ),
        }
        network["capture"] = {
            "path": capture.get("pcap"),
            "counts": capture.get("counts", {}),
            "sessions": capture.get("sessions", {}),
            "warnings": capture.get("warnings", []),
            "raw_event_occurrences": len(capture.get("events") or []),
            "display_event_rows": len(
                capture.get("display_events") or capture.get("events") or []
            ),
            "protocol_occurrences": protocol_occurrences,
        }
        network["attribution"] = capture.get("attribution", {})

    # Decrypted streams are additive: they carry the plaintext of requests the sources above
    # could only see the metadata of, and they also count as HTTP requests for signatures.
    if decrypted:
        for key in ("http_ex", "https_ex", "smtp_ex"):
            entries = decrypted.get(key) or []
            if entries:
                network[key] = entries

        for entry in (decrypted.get("http_ex") or []) + (decrypted.get("https_ex") or []):
            collector.AddHttp(
                method=entry.get("method") or "GET",
                host=entry.get("host") or "",
                path=entry.get("uri") or "/",
                data=entry.get("request") or "",
                src=entry.get("src"),
                sport=entry.get("sport"),
                dst=entry.get("dst"),
                dport=entry.get("dport"),
                time=entry.get("first_seen") or entry.get("time"),
                occurrence=False,
                observation_source="decrypted",
            )
            collector.AddHost(entry.get("dst") or "")

        for entry in decrypted.get("smtp_ex") or []:
            network["smtp"].append(
                {
                    "dst": entry.get("dst") or "",
                    "dport": entry.get("dport") or 0,
                    "req": entry.get("req") or {},
                }
            )

        if any(decrypted.get(k) for k in ("http_ex", "https_ex", "smtp_ex")):
            collector.Source("decrypted")

        # Carry the decryption status so a report can explain a thin or empty Plaintext
        # section - a missing dependency, no secrets, or a truncated capture - the way the
        # Network tab does, instead of leaving the reader to guess why it decrypted nothing.
        network["decrypted"] = {
            "available": decrypted.get("available", False),
            "secrets": decrypted.get("secrets", 0),
            "error": decrypted.get("error", ""),
            "engine": decrypted.get("engine", {}),
            "key_material": decrypted.get("key_material", {}),
            "counts": {
                key: len(decrypted.get(key) or [])
                for key in ("http_ex", "https_ex", "smtp_ex")
            },
        }

    class_counts = {}
    for section in ("http", "http_responses", "dns", "tls", "tcp", "udp"):
        for entry in network.get(section) or []:
            name = str(entry.get("traffic_class") or "unclassified")
            class_counts[name] = class_counts.get(name, 0) + 1
    network["traffic_classification"] = {
        "counts": class_counts,
        "raw_entries_removed": 0,
        "signature_gate": "skip_only_when_signature_eligible_is_false",
    }

    return network
