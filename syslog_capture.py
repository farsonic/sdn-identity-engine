"""
Syslog listener for the SDN Identity Engine.

Listens on a UDP port for syslog messages (the Omada controller can be told to
forward its log to this host). Parses standard RFC 3164 / RFC 5424 framing,
then applies Omada-specific extraction to pull out the event category, client
MAC, AP/switch name, SSID, etc. Each parsed event is handed to an on_event
callback for persistence.

Design mirrors dhcp_capture.DHCPCapture: a background daemon thread owning a
socket, with a status() snapshot for the dashboard. No external deps — uses the
stdlib socket module (syslog is just UDP text).
"""

from __future__ import annotations

import logging
import re
import socket
import threading
from datetime import datetime, timezone
from typing import Callable, Optional

log = logging.getLogger("omada-app")

# Callback signature: on_event(parsed_event: dict) -> None
EventCallback = Callable[[dict], None]

# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

# RFC 3164:  <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
#   e.g. <134>Jan  1 12:00:00 OC200 Omada[1234]: [Clients] ...
# RFC 5424:  <PRI>VERSION TIMESTAMP HOSTNAME APP PROCID MSGID [SD] MSG
#   e.g. <134>1 2026-05-20T12:00:00Z OC200 Omada - - - [Clients] ...
_PRI_RE = re.compile(r"^<(\d{1,3})>")
_RFC3164_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:?\s*"
    r"(?P<msg>.*)$"
)
_RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d)\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<rest>.*)$"
)

# MAC in either colon or dash form, anywhere in the message.
_MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b")
# An IPv4 address.
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Omada tags its events with a bracketed category, e.g. "[Clients]", "[Device]".
_CATEGORY_RE = re.compile(r"\[([A-Za-z][A-Za-z0-9 _/-]+)\]")

# Omada firewall/flow log format (very high volume). Example:
#   AP MAC=1c:61:b4:98:80:3a MAC SRC=78:46:5c:01:27:3f IP SRC=192.168.0.56
#   IP DST=52.119.41.59 IP proto=6 SPT=62321 DPT=443
# Here the *client* is "MAC SRC" — "AP MAC" is the access point relaying it.
_FLOW_AP_MAC_RE = re.compile(r"AP MAC=([0-9A-Fa-f:]{17})", re.I)
_FLOW_SRC_MAC_RE = re.compile(r"MAC SRC=([0-9A-Fa-f:]{17})", re.I)
_FLOW_IP_SRC_RE = re.compile(r"IP SRC=(\d{1,3}(?:\.\d{1,3}){3})", re.I)
_FLOW_IP_DST_RE = re.compile(r"IP DST=(\d{1,3}(?:\.\d{1,3}){3})", re.I)
_FLOW_PROTO_RE = re.compile(r"IP proto=(\d+)", re.I)
_FLOW_DPT_RE = re.compile(r"\bDPT=(\d+)", re.I)
# SSID often appears as: with SSID "Foo" / SSID Foo / on WLAN "Foo"
_SSID_RE = re.compile(r'SSID[:\s]+"?([^"\,\.]+?)"?(?:\s|$|,|\.)', re.IGNORECASE)
# Channel: "on channel 36" / "channel: 36"
_CHANNEL_RE = re.compile(r"channel[:\s]+(\d+)", re.IGNORECASE)

# Facility/severity decode from the PRI value (PRI = facility*8 + severity).
_SEVERITY = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
_FACILITY = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]

# Keyword → normalized event_type. Order matters (first match wins). These are
# matched case-insensitively against the message body so the dashboard and AI
# can group/filter without re-parsing free text every time.
_EVENT_KEYWORDS = [
    ("auth_failed",   ["authentication failed", "auth failed", "failed to authenticate",
                       "eap failure", "802.1x", "radius reject", "wrong password",
                       "invalid password"]),
    ("client_connect",    ["is connected to", "connected to ssid", "online", "associated",
                           "has come online", "joined"]),
    ("client_disconnect", ["is disconnected", "disconnected from", "offline", "deauth",
                           "disassociat", "has gone offline", "left"]),
    ("roaming",       ["roamed", "roaming", "handoff", "fast roaming", "ft "]),
    ("dhcp",          ["dhcp", "lease", "ip assigned", "renewed"]),
    ("device_event",  ["was connected", "was disconnected", "adopted", "provisioning",
                       "rebooted", "upgrade", "firmware", "reconnect", "isolated"]),
    ("wireless_issue",["interference", "high channel utilization", "dfs", "radar",
                       "noise", "retries", "low rssi", "weak signal"]),
    ("system",        ["system", "controller", "backup", "login", "logout",
                       "config", "settings changed"]),
]


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def decode_pri(pri: int) -> tuple[str, str]:
    """Return (facility_name, severity_name) for a syslog PRI value."""
    sev = pri & 0x07
    fac = pri >> 3
    fac_name = _FACILITY[fac] if 0 <= fac < len(_FACILITY) else f"facility{fac}"
    sev_name = _SEVERITY[sev] if 0 <= sev < len(_SEVERITY) else f"sev{sev}"
    return fac_name, sev_name


def classify_event(message: str) -> str:
    """Map a message body to a normalized event_type using keyword matching."""
    low = message.lower()
    for event_type, keywords in _EVENT_KEYWORDS:
        for kw in keywords:
            if kw in low:
                return event_type
    return "other"


def parse_syslog(raw: str, source_ip: str) -> dict:
    """Parse a single raw syslog line into a structured dict. Always returns a
    dict (never raises) — unparseable lines still get stored with raw text so
    nothing is silently dropped."""
    raw = raw.rstrip("\x00").strip()
    now = _iso_now()
    event = {
        "received_at": now,
        "source_ip": source_ip,
        "raw": raw[:2000],
        "pri": None,
        "facility": None,
        "severity": None,
        "syslog_ts": None,
        "hostname": None,
        "tag": None,
        "message": raw[:2000],
        "category": None,
        "event_type": "other",
        "client_mac": None,
        "client_ip": None,
        "ssid": None,
        "channel": None,
        "device_name": None,
    }

    # Try RFC 5424 first (has explicit version digit after PRI), then 3164.
    m = _RFC5424_RE.match(raw)
    if m:
        event["pri"] = int(m.group("pri"))
        event["syslog_ts"] = m.group("ts")
        event["hostname"] = m.group("host")
        event["tag"] = m.group("app")
        event["message"] = m.group("rest")[:2000]
    else:
        m = _RFC3164_RE.match(raw)
        if m:
            event["pri"] = int(m.group("pri"))
            event["syslog_ts"] = m.group("ts")
            event["hostname"] = m.group("host")
            event["tag"] = m.group("tag")
            event["message"] = m.group("msg")[:2000]
        else:
            # No standard framing — maybe just "<PRI>freeform" or bare text.
            pm = _PRI_RE.match(raw)
            if pm:
                event["pri"] = int(pm.group(1))
                event["message"] = raw[pm.end():][:2000]

    if event["pri"] is not None:
        event["facility"], event["severity"] = decode_pri(event["pri"])

    body = event["message"] or ""

    # Bracketed Omada category, e.g. "[Clients]".
    cm = _CATEGORY_RE.search(body)
    if cm:
        event["category"] = cm.group(1).strip()

    # Extract identifiers from the body.
    # First check for the high-volume firewall/flow-log format, where the
    # client is "MAC SRC=" and "AP MAC=" is the access point — naive
    # first-MAC matching would wrongly attribute every flow to the AP.
    flow_src = _FLOW_SRC_MAC_RE.search(body)
    flow_ap = _FLOW_AP_MAC_RE.search(body)
    if flow_src:
        event["client_mac"] = flow_src.group(1).upper().replace(":", "-")
        if flow_ap:
            event["device_name"] = flow_ap.group(1).upper().replace(":", "-")
        ipsrc = _FLOW_IP_SRC_RE.search(body)
        if ipsrc:
            event["client_ip"] = ipsrc.group(1)
        event["event_type"] = "traffic_flow"
        # Stash dest + dport for traffic graphs (top destinations / ports).
        ipdst = _FLOW_IP_DST_RE.search(body)
        if ipdst:
            event["dest_ip"] = ipdst.group(1)
        dpt = _FLOW_DPT_RE.search(body)
        if dpt:
            try:
                event["dest_port"] = int(dpt.group(1))
            except ValueError:
                pass
        return event

    macs = _MAC_RE.findall(body)
    if macs:
        # findall returns the last group; re-find full matches instead.
        full = _MAC_RE.search(body)
        if full:
            event["client_mac"] = full.group(0).upper().replace(":", "-")
    ipm = _IP_RE.search(body)
    if ipm and ipm.group(0) != source_ip:
        event["client_ip"] = ipm.group(0)
    sm = _SSID_RE.search(body)
    if sm:
        event["ssid"] = sm.group(1).strip()[:64]
    chm = _CHANNEL_RE.search(body)
    if chm:
        try:
            event["channel"] = int(chm.group(1))
        except ValueError:
            pass

    event["event_type"] = classify_event(body)
    return event


# ---------------------------------------------------------------------------
# Listener
# ---------------------------------------------------------------------------

class SyslogCapture:
    """UDP syslog listener. Binds 0.0.0.0:<port>, parses each datagram, and
    hands the structured event to on_event."""

    def __init__(self, port: int, on_event: EventCallback,
                 bind_addr: str = "0.0.0.0"):
        self.port = int(port)
        self.bind_addr = bind_addr
        self.on_event = on_event
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None

        self.messages_received = 0
        self.events_stored = 0
        self.parse_errors = 0
        self.last_message_at: Optional[str] = None
        self.last_source_ip: Optional[str] = None
        self.error: Optional[str] = None
        self.running = False
        self.started_at: Optional[str] = None

    def start(self) -> bool:
        import os
        if os.environ.get("WERKZEUG_RUN_MAIN") == "false":
            log.info("Skipping syslog listener in reloader watcher process")
            return False
        if self._thread and self._thread.is_alive():
            return True
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="syslog-listener"
        )
        self._thread.start()
        self.started_at = _iso_now()
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def status(self) -> dict:
        return {
            "enabled": True,
            "running": self.running,
            "listen_port": self.port,
            "bind_addr": self.bind_addr,
            "messages_received": self.messages_received,
            "events_stored": self.events_stored,
            "parse_errors": self.parse_errors,
            "last_message_at": self.last_message_at,
            "last_source_ip": self.last_source_ip,
            "error": self.error,
            "started_at": self.started_at,
        }

    def _run(self) -> None:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.bind_addr, self.port))
            self._sock.settimeout(1.0)
        except OSError as exc:
            self.error = (
                f"Failed to bind syslog UDP {self.bind_addr}:{self.port}: {exc}. "
                f"Port <1024 needs privilege — use a high port like 5514 and "
                f"point Omada at it, or run with NET_BIND_SERVICE."
            )
            log.error(self.error)
            return

        self.running = True
        log.info("Syslog listener live on UDP %s:%d", self.bind_addr, self.port)
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                continue
            self.messages_received += 1
            self.last_source_ip = addr[0]
            self.last_message_at = _iso_now()
            # A single datagram may contain multiple newline-separated messages.
            text = data.decode("utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    event = parse_syslog(line, addr[0])
                    self.on_event(event)
                    self.events_stored += 1
                except Exception:
                    self.parse_errors += 1
                    log.exception("Failed to handle syslog line: %r", line[:200])
        self.running = False
        log.info("Syslog listener stopped")
