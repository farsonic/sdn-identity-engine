"""
SDN Identity Engine — Omada client name reconciliation.

Configuration via environment variables, OR set them in the Settings view
at runtime (DB-stored values override env-var defaults):

    OMADA_URL              https://controller.example.com   (required)
    OMADA_CLIENT_ID        Open API application client ID    (required)
    OMADA_CLIENT_SECRET    Open API application client secret (required)
    OMADA_VERIFY_TLS       "1" to verify the controller cert, else skip
    FINGERBANK_API_KEY     api.fingerbank.org key (optional, free tier OK)
    GEMINI_API_KEY         aistudio.google.com key (optional, enables AI)
    NAMING_DEFAULT_TEMPLATE  default template if DB is empty

Set these via docker-compose `environment:` block, or leave them empty and
configure everything via the Settings page on first launch.
"""

import json
import logging
import os
import re
import threading
import time

import requests
import urllib3
from flask import Flask, jsonify, render_template, request
from flask_sqlalchemy import SQLAlchemy

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
OMADA_URL = os.environ.get("OMADA_URL", "").rstrip("/")
OMADA_CLIENT_ID = os.environ.get("OMADA_CLIENT_ID", "")
OMADA_CLIENT_SECRET = os.environ.get("OMADA_CLIENT_SECRET", "")
OMADA_VERIFY_TLS = os.environ.get("OMADA_VERIFY_TLS", "0") == "1"

FINGERBANK_API_KEY = os.environ.get("FINGERBANK_API_KEY", "")
FINGERBANK_URL = "https://api.fingerbank.org/api/v2/combinations/interrogate"

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
# Default if no DB setting is saved. User can override per-request via the UI.
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.1-pro-preview")

# Selectable models — ordered roughly by capability/cost (best first).
# Keep this list short and well-labelled; the UI surfaces them as-is.
GEMINI_MODELS = [
    {"id": "gemini-3.1-pro-preview",        "label": "3.1 Pro Preview",   "tier": "best reasoning · slowest · priciest"},
    {"id": "gemini-3.1-flash-preview",      "label": "3.1 Flash Preview", "tier": "newest Flash · fast · cheap"},
    {"id": "gemini-3.1-flash-lite-preview", "label": "3.1 Flash-Lite",    "tier": "cheapest · low-latency"},
    {"id": "gemini-2.5-pro",                "label": "2.5 Pro (stable)",  "tier": "stable Pro · production"},
    {"id": "gemini-2.5-flash",              "label": "2.5 Flash (stable)","tier": "stable Flash · production"},
    {"id": "gemini-2.5-flash-lite",         "label": "2.5 Flash-Lite",    "tier": "stable cheapest"},
]
GEMINI_MODEL_IDS = {m["id"] for m in GEMINI_MODELS}

DEFAULT_TEMPLATE = os.environ.get("NAMING_DEFAULT_TEMPLATE", "{name} - {os} - {type}")

# DHCP capture via TZSP forwarding (e.g. MikroTik's Tools > Packet Sniffer).
# Capture configuration. Two modes:
#   tzsp (default, backward-compatible): listen on UDP/<port> for TZSP-
#     encapsulated forwards from an upstream router (e.g. MikroTik). Works
#     with default Docker bridge networking; only needs the port exposed.
#   local: sniff the host's NIC directly with scapy + BPF filter. Captures
#     mDNS multicast that Docker bridge can never forward inward. Requires
#     `network_mode: host` and `cap_add: [NET_RAW]` in docker-compose.
DHCP_CAPTURE_ENABLED = os.environ.get("DHCP_CAPTURE_ENABLED", "1") == "1"
DHCP_CAPTURE_PORT = int(os.environ.get("DHCP_CAPTURE_PORT", "37008"))
CAPTURE_MODE = os.environ.get("CAPTURE_MODE", "tzsp").lower().strip()
# In local mode, optionally name the interface to sniff (e.g. "eth0").
# Empty string means scapy auto-picks the default interface, which is
# usually fine on a single-NIC container in host-network mode.
CAPTURE_INTERFACE = os.environ.get("CAPTURE_INTERFACE", "").strip()

# Syslog ingestion. Omada (or any device) can forward syslog here for
# storage + AI analysis. Default port 5514 (high port, no privilege needed).
# Set SYSLOG_ENABLED=0 to disable. SYSLOG_MAX_ROWS caps stored events; the
# oldest are pruned past this count to bound disk use (syslog is high-volume).
SYSLOG_ENABLED = os.environ.get("SYSLOG_ENABLED", "1") == "1"
SYSLOG_PORT = int(os.environ.get("SYSLOG_PORT", "5514"))
SYSLOG_MAX_ROWS = int(os.environ.get("SYSLOG_MAX_ROWS", "100000"))
# Omada firewall/flow logging is extremely high-volume and mostly noise for
# AIOps. With this set, traffic_flow events are dropped at ingest (counted but
# not stored), so the table stays full of meaningful lifecycle events
# (connect/roam/auth/DHCP/AP-state) and the row cap buys far more history.
# Toggle live from the Syslog view; persisted in GlobalSetting.
SYSLOG_DROP_TRAFFIC_FLOW = os.environ.get("SYSLOG_DROP_TRAFFIC_FLOW", "0") == "1"
# Optional shared secret for the webhook receiver. If set, Omada must POST to
# /api/webhook/<token>. If empty, the endpoint is open (LAN-trusted).
WEBHOOK_TOKEN = os.environ.get("WEBHOOK_TOKEN", "")

if not OMADA_VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
)
log = logging.getLogger("omada-app")

# ---------------------------------------------------------------------------
# Flask & DB
# ---------------------------------------------------------------------------
app = Flask(__name__)
db_path = os.path.join(app.root_path, "instance", "settings.db")
os.makedirs(os.path.dirname(db_path), exist_ok=True)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class GlobalSetting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    naming_template = db.Column(db.String(256), default=DEFAULT_TEMPLATE)
    gemini_model = db.Column(db.String(64))
    # Stored credentials — these override the ENV defaults on startup and after
    # any save through /api/config. Empty/null falls back to ENV. Stored in
    # plaintext (single-tenant homelab tool); rotate in /api/config UI.
    omada_url = db.Column(db.String(256))
    omada_client_id = db.Column(db.String(128))
    omada_client_secret = db.Column(db.String(256))
    gemini_api_key = db.Column(db.String(256))
    fingerbank_api_key = db.Column(db.String(256))
    # Shared bearer token the Android companion app presented on /api/telemetry.
    # Retained as a column for backward compat with existing DBs; no longer used.
    telemetry_token = db.Column(db.String(128))
    # When set, traffic_flow (firewall/flow) syslog events are dropped at ingest.
    drop_traffic_flow = db.Column(db.Boolean, default=False)


class SyslogEvent(db.Model):
    """A parsed syslog message forwarded by the Omada controller (or any
    syslog source). High-volume — pruned to SYSLOG_MAX_ROWS by age. Indexed
    on received_at (timeline queries) and client_mac (per-device correlation)."""
    id = db.Column(db.Integer, primary_key=True)
    received_at = db.Column(db.String(32), index=True)  # when we got it (ISO UTC)
    source_ip = db.Column(db.String(45))                # syslog sender
    pri = db.Column(db.Integer)
    facility = db.Column(db.String(16))
    severity = db.Column(db.String(16), index=True)
    syslog_ts = db.Column(db.String(48))                # timestamp from the message
    hostname = db.Column(db.String(64))
    tag = db.Column(db.String(64))
    message = db.Column(db.Text)
    category = db.Column(db.String(48))                 # Omada [bracketed] category
    event_type = db.Column(db.String(32), index=True)   # normalized classification
    client_mac = db.Column(db.String(17), index=True)   # extracted, dash-upper
    client_ip = db.Column(db.String(45))
    ssid = db.Column(db.String(64))
    channel = db.Column(db.Integer)
    device_name = db.Column(db.String(64))
    raw = db.Column(db.Text)


class DeviceSetting(db.Model):
    mac = db.Column(db.String(17), primary_key=True)
    auto_sync = db.Column(db.Boolean, default=False)
    last_synced_name = db.Column(db.String(256))
    fingerbank_cache = db.Column(db.Text)
    ai_analysis = db.Column(db.Text)
    ai_analyzed_at = db.Column(db.String(32))
    notes = db.Column(db.Text)
    first_seen = db.Column(db.String(32))
    last_seen = db.Column(db.String(32))
    dhcp_fingerprint = db.Column(db.String(256))     # option 55 parameter request list
    dhcp_vendor_class = db.Column(db.String(256))    # option 60 vendor class identifier
    dhcp_captured_at = db.Column(db.String(32))
    # mDNS observations — JSON with {services: [...], txt: {...},
    # instance_names: [...], last_seen: iso, packet_count: int}.
    # Accumulated across multiple captures; services and instance_names
    # are unioned, txt records are last-write-wins.
    mdns_data = db.Column(db.Text)
    mdns_captured_at = db.Column(db.String(32))


def _migrate_sqlite_schema() -> None:
    """Add new columns on existing DBs. db.create_all() creates tables but
    won't ALTER existing ones."""
    from sqlalchemy import inspect, text

    inspector = inspect(db.engine)
    tables = inspector.get_table_names()

    migrations = {
        "device_setting": [
            ("ai_analysis", "TEXT"),
            ("ai_analyzed_at", "VARCHAR(32)"),
            ("notes", "TEXT"),
            ("first_seen", "VARCHAR(32)"),
            ("last_seen", "VARCHAR(32)"),
            ("dhcp_fingerprint", "VARCHAR(256)"),
            ("dhcp_vendor_class", "VARCHAR(256)"),
            ("dhcp_captured_at", "VARCHAR(32)"),
            ("mdns_data", "TEXT"),
            ("mdns_captured_at", "VARCHAR(32)"),
        ],
        "global_setting": [
            ("gemini_model", "VARCHAR(64)"),
            ("omada_url", "VARCHAR(256)"),
            ("omada_client_id", "VARCHAR(128)"),
            ("omada_client_secret", "VARCHAR(256)"),
            ("gemini_api_key", "VARCHAR(256)"),
            ("fingerbank_api_key", "VARCHAR(256)"),
            ("drop_traffic_flow", "BOOLEAN"),
        ],
    }

    with db.engine.connect() as conn:
        for table, cols in migrations.items():
            if table not in tables:
                continue
            existing = {c["name"] for c in inspector.get_columns(table)}
            for col, coltype in cols:
                if col not in existing:
                    log.info("Migrating: adding %s.%s", table, col)
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {coltype}"))
        conn.commit()


with app.app_context():
    db.create_all()
    _migrate_sqlite_schema()


def reload_app_config() -> None:
    """Pull credentials from the GlobalSetting row, override the module-level
    constants. Called on startup and after every /api/config PUT. Empty or
    NULL fields are skipped, leaving the ENV defaults in place — that's how
    a fresh install bootstraps from docker-compose envvars and a configured
    install runs entirely from the DB."""
    global OMADA_URL, OMADA_CLIENT_ID, OMADA_CLIENT_SECRET
    global GEMINI_API_KEY, FINGERBANK_API_KEY
    with app.app_context():
        row = GlobalSetting.query.first()
        if row is None:
            return
        if row.omada_url:
            OMADA_URL = row.omada_url.rstrip("/")
        if row.omada_client_id:
            OMADA_CLIENT_ID = row.omada_client_id
        if row.omada_client_secret:
            OMADA_CLIENT_SECRET = row.omada_client_secret
        if row.gemini_api_key:
            GEMINI_API_KEY = row.gemini_api_key
        if row.fingerbank_api_key:
            FINGERBANK_API_KEY = row.fingerbank_api_key


reload_app_config()


# ---------------------------------------------------------------------------
# DHCP passive capture
# ---------------------------------------------------------------------------
# ====================================================================
# Fingerbank auto-lookup helpers
#
# When a DHCP fingerprint is captured (or already in the DB) and no
# Fingerbank cache exists yet, we kick off an automatic lookup in a
# daemon thread. Deduped by MAC so concurrent triggers (DHCP capture +
# /api/clients poll arriving at the same moment) only result in one
# API call. Manual /api/refresh_fingerbank still works for re-runs.
# ====================================================================

_fingerbank_inflight: set[str] = set()
_fingerbank_lock = threading.Lock()


def _fingerbank_lookup_sync(mac: str,
                            fingerprint: str | None,
                            vendor_class: str | None,
                            user_agent: str | None = None) -> dict | None:
    """Synchronous Fingerbank HTTP call. Returns response dict or None on error.
    Does NOT persist — caller stores the result."""
    if not FINGERBANK_API_KEY:
        return None
    payload = {"mac": mac.replace(":", "").replace("-", "").lower()}
    if fingerprint:
        payload["dhcp_fingerprint"] = fingerprint
    if vendor_class:
        payload["dhcp_vendor"] = vendor_class
    if user_agent:
        payload["user_agents"] = [user_agent]
    try:
        r = requests.post(
            FINGERBANK_URL,
            params={"key": FINGERBANK_API_KEY},
            json=payload,
            timeout=8,
        )
        return r.json()
    except Exception:
        log.exception("Fingerbank lookup failed for %s", mac)
        return None


def _fingerbank_auto_lookup_for_mac(mac: str) -> bool:
    """Read the device's stored DHCP fingerprint, call Fingerbank, persist
    the result. Runs inside the daemon thread. Returns True on success."""
    with app.app_context():
        setting = db.session.get(DeviceSetting, mac)
        if not setting:
            return False
        fp = setting.dhcp_fingerprint
        vc = setting.dhcp_vendor_class
        if not fp and not vc:
            # Nothing to query with — skip silently (caller already filtered,
            # this is just defensive).
            return False
        fb_data = _fingerbank_lookup_sync(mac, fp, vc)
        if fb_data is None:
            return False
        fb_data["_request"] = {
            "fingerprint_used": fp,
            "vendor_used": vc,
            "fingerprint_source": "captured" if fp else "none",
            "auto": True,
        }
        # Re-fetch in case another thread modified the row meanwhile.
        setting = db.session.get(DeviceSetting, mac)
        if not setting:
            return False
        setting.fingerbank_cache = json.dumps(fb_data)
        db.session.add(setting)
        db.session.commit()
        device_name = (fb_data.get("device") or {}).get("name", "?")
        log.info("Auto-Fingerbank for %s → %s", mac, device_name)
        return True


def _async_fingerbank_lookup(mac: str) -> None:
    """Fire a Fingerbank lookup in a daemon thread, deduped by MAC.
    Safe to call from request handlers and from the DHCP capture thread."""
    if not FINGERBANK_API_KEY:
        return
    with _fingerbank_lock:
        if mac in _fingerbank_inflight:
            return
        _fingerbank_inflight.add(mac)

    def _run() -> None:
        try:
            _fingerbank_auto_lookup_for_mac(mac)
        except Exception:
            log.exception("Async Fingerbank lookup crashed for %s", mac)
        finally:
            with _fingerbank_lock:
                _fingerbank_inflight.discard(mac)

    threading.Thread(target=_run, daemon=True, name=f"fb-auto-{mac[-5:]}").start()


def _store_dhcp_capture(mac: str, fingerprint: str | None,
                         vendor_class: str | None, hostname: str | None) -> None:
    """Callback for the scapy thread. Writes captured fingerprint to DB.
    Idempotent — won't commit if nothing changed."""
    with app.app_context():
        setting = db.session.get(DeviceSetting, mac)
        now = iso_now()
        if setting is None:
            setting = DeviceSetting(
                mac=mac, auto_sync=False,
                first_seen=now, last_seen=now,
                dhcp_fingerprint=fingerprint,
                dhcp_vendor_class=vendor_class,
                dhcp_captured_at=now,
            )
            db.session.add(setting)
            db.session.commit()
            log.info("Captured DHCP fingerprint for %s: fp=%s vendor=%r hn=%r",
                     mac, fingerprint, vendor_class, hostname)
            # No fingerbank_cache exists for this brand-new device — auto-query.
            _async_fingerbank_lookup(mac)
            return

        changed = False
        if fingerprint and setting.dhcp_fingerprint != fingerprint:
            setting.dhcp_fingerprint = fingerprint
            changed = True
        if vendor_class and setting.dhcp_vendor_class != vendor_class:
            setting.dhcp_vendor_class = vendor_class
            changed = True
        had_cache = bool(setting.fingerbank_cache)
        if changed:
            setting.dhcp_captured_at = now
            db.session.commit()
            log.info("Updated DHCP fingerprint for %s: fp=%s vendor=%r",
                     mac, fingerprint, vendor_class)
        # Auto-query Fingerbank if (a) no cache exists yet, or (b) the
        # fingerprint actually changed. Stable fingerprints with an existing
        # cache are left alone — user can hit refresh manually if they want.
        if changed or not had_cache:
            _async_fingerbank_lookup(mac)


def _store_mdns_capture(mac: str, services: list, txt_records: dict,
                         instance_names: list) -> None:
    """Callback for the TZSP listener's mDNS branch. Merges observations into
    the DeviceSetting.mdns_data JSON column.

    Multiple captures of the same device should accumulate, not overwrite:
      - services and instance_names are set-unioned across observations
      - txt records are last-write-wins (so model/firmware updates flow through)
      - packet_count tracks how many mDNS packets we've seen from this MAC
    """
    if not (services or txt_records or instance_names):
        return

    with app.app_context():
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        setting = db.session.get(DeviceSetting, mac)
        if setting is None:
            # Brand-new MAC, only known via mDNS so far (no Omada record yet,
            # no DHCP captured). Create a stub so we don't lose the data.
            setting = DeviceSetting(
                mac=mac, auto_sync=False,
                first_seen=now, last_seen=now,
            )
            db.session.add(setting)

        # Decode existing mDNS observations.
        try:
            existing = json.loads(setting.mdns_data) if setting.mdns_data else {}
        except (json.JSONDecodeError, TypeError):
            existing = {}

        merged_services = sorted(set(existing.get("services", [])) | set(services))
        # Case-insensitive dedup for instance names too.
        existing_instances = existing.get("instance_names", [])
        seen_lc: set = set()
        merged_instances: list = []
        for inst in list(existing_instances) + list(instance_names):
            key = inst.lower() if isinstance(inst, str) else inst
            if key not in seen_lc:
                seen_lc.add(key)
                merged_instances.append(inst)

        merged_txt = dict(existing.get("txt", {}))
        merged_txt.update(txt_records)  # last-write-wins

        new_data = {
            "services": merged_services,
            "txt": merged_txt,
            "instance_names": merged_instances,
            "first_seen": existing.get("first_seen") or now,
            "last_seen": now,
            "packet_count": int(existing.get("packet_count", 0)) + 1,
        }

        # Only commit if something actually changed (avoid hammering SQLite
        # on repeated identical announcements, which are common — devices
        # multicast their service list every few minutes).
        changed = (
            new_data["services"] != existing.get("services") or
            new_data["txt"] != existing.get("txt") or
            new_data["instance_names"] != existing.get("instance_names")
        )

        setting.mdns_data = json.dumps(new_data)
        setting.mdns_captured_at = now
        db.session.add(setting)
        db.session.commit()

        if changed:
            top_service = merged_services[0] if merged_services else "?"
            log.info("mDNS for %s: %d services (%s...), %d txt keys, %d instances",
                     mac, len(merged_services), top_service,
                     len(merged_txt), len(merged_instances))


from dhcp_capture import DHCPCapture, LocalSniffer  # noqa: E402

if CAPTURE_MODE == "local":
    dhcp_capture = LocalSniffer(
        CAPTURE_INTERFACE,
        _store_dhcp_capture,
        on_mdns=_store_mdns_capture,
    )
    log.info("Capture mode: local (sniffing %s)",
             CAPTURE_INTERFACE or "auto-detected interface")
else:
    dhcp_capture = DHCPCapture(
        DHCP_CAPTURE_PORT,
        _store_dhcp_capture,
        on_mdns=_store_mdns_capture,
    )
    log.info("Capture mode: tzsp (listening on UDP/%d)", DHCP_CAPTURE_PORT)

if DHCP_CAPTURE_ENABLED:
    dhcp_capture.start()
else:
    log.info("Capture disabled via DHCP_CAPTURE_ENABLED=0")


# --- Syslog ingestion -------------------------------------------------------
_syslog_event_count = 0   # cheap in-process counter to throttle prune frequency
_syslog_dropped_count = 0  # traffic_flow events dropped at ingest this process
_webhook_count = 0  # webhook notifications received this process
# Live, mutable copy of the drop-flow flag. Seeded from env; the DB value (if
# set) overrides it at startup via reload_app_config(); the UI toggle updates
# both this and the DB.
_drop_traffic_flow = SYSLOG_DROP_TRAFFIC_FLOW

# DB override at startup: if a GlobalSetting row has drop_traffic_flow set,
# honour it over the env default.
with app.app_context():
    _gs_row = GlobalSetting.query.first()
    if _gs_row is not None and _gs_row.drop_traffic_flow is not None:
        _drop_traffic_flow = bool(_gs_row.drop_traffic_flow)
        if _drop_traffic_flow:
            log.info("Syslog: dropping traffic_flow events at ingest (from DB setting)")


def _store_syslog_event(event: dict) -> None:
    """Callback for the syslog listener thread. Persists a parsed event and
    periodically prunes old rows. Also bumps the matched client's last_seen
    so syslog activity keeps a device 'fresh' between Omada polls.

    If drop-traffic-flow is enabled, firewall/flow events are counted but not
    stored — keeps the table full of meaningful lifecycle events."""
    global _syslog_event_count, _syslog_dropped_count
    if _drop_traffic_flow and event.get("event_type") == "traffic_flow":
        _syslog_dropped_count += 1
        return
    with app.app_context():
        row = SyslogEvent(
            received_at=event.get("received_at"),
            source_ip=event.get("source_ip"),
            pri=event.get("pri"),
            facility=event.get("facility"),
            severity=event.get("severity"),
            syslog_ts=event.get("syslog_ts"),
            hostname=event.get("hostname"),
            tag=event.get("tag"),
            message=event.get("message"),
            category=event.get("category"),
            event_type=event.get("event_type"),
            client_mac=event.get("client_mac"),
            client_ip=event.get("client_ip"),
            ssid=event.get("ssid"),
            channel=event.get("channel"),
            device_name=event.get("device_name"),
            raw=event.get("raw"),
        )
        db.session.add(row)

        # Correlate to a known device and bump last_seen.
        mac = event.get("client_mac")
        if mac:
            setting = db.session.get(DeviceSetting, mac)
            if setting is not None:
                setting.last_seen = event.get("received_at")
        db.session.commit()

        _syslog_event_count += 1
        # Prune every 500 events rather than on every insert.
        if _syslog_event_count % 500 == 0:
            _prune_syslog()


def _prune_syslog() -> None:
    """Keep only the most recent SYSLOG_MAX_ROWS rows."""
    with app.app_context():
        total = db.session.query(SyslogEvent.id).count()
        if total <= SYSLOG_MAX_ROWS:
            return
        excess = total - SYSLOG_MAX_ROWS
        old_ids = [r.id for r in SyslogEvent.query
                   .order_by(SyslogEvent.id.asc()).limit(excess).all()]
        if old_ids:
            SyslogEvent.query.filter(SyslogEvent.id.in_(old_ids)).delete(
                synchronize_session=False)
            db.session.commit()
            log.info("Pruned %d old syslog rows (cap=%d)", len(old_ids), SYSLOG_MAX_ROWS)


from syslog_capture import SyslogCapture  # noqa: E402

syslog_capture = SyslogCapture(SYSLOG_PORT, _store_syslog_event)
if SYSLOG_ENABLED:
    syslog_capture.start()
    log.info("Syslog ingestion enabled (UDP/%d)", SYSLOG_PORT)
else:
    log.info("Syslog ingestion disabled via SYSLOG_ENABLED=0")


def get_setting(mac: str) -> DeviceSetting | None:
    """SQLAlchemy 2.x-friendly lookup."""
    return db.session.get(DeviceSetting, mac)


def iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_recent(iso_str: str | None, days: int = 7) -> bool:
    """True if iso_str is within the last `days` days. None or unparseable -> False."""
    if not iso_str:
        return False
    from datetime import datetime, timezone, timedelta
    try:
        ts = datetime.strptime(iso_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return ts >= datetime.now(timezone.utc) - timedelta(days=days)


def build_template_ctx(c: dict, fb_cache: dict, ai_cache: dict, notes: str | None) -> dict:
    """Compose the template-substitution context with AI-first precedence.

    For each field, the order of preference is:
      AI structured output  >  Omada/Fingerbank value  >  hostname  >  "Unknown"

    Returns a dict suitable for render_template_name().
    """
    host = c.get("hostName") or c.get("name") or "Unknown-Host"

    ai_short = (ai_cache.get("short_name") or "").strip()
    ai_os    = (ai_cache.get("normalized_os") or "").strip()
    ai_type  = (ai_cache.get("normalized_type") or "").strip()
    ai_mfr   = (ai_cache.get("manufacturer") or "").strip()

    # Name: AI's concise label > DHCP hostname > literal "Device"
    name = ai_short or host
    if name == "Unknown-Host":
        name = "Device"

    # OS: AI value (skip if Unknown — fall through to Omada/Fingerbank) > Omada > Fingerbank > Unknown
    fb_os = fb_cache.get("device", {}).get("name") if fb_cache else None
    if ai_os and ai_os != "Unknown":
        os_name = ai_os
    else:
        os_name = c.get("osName") or c.get("os") or fb_os or "Unknown"

    # Type: AI value (skip if Other) > Omada deviceType > "Unknown"
    if ai_type and ai_type != "Other":
        type_name = ai_type
    else:
        type_name = c.get("deviceType") or "Unknown"

    # Vendor: AI manufacturer > Omada > Fingerbank > "Unknown-NIC"
    fb_mfr = (fb_cache.get("manufacturer", {}) or {}).get("name") if fb_cache else None
    vendor = (
        ai_mfr
        or (c.get("vendor") if c.get("vendor") not in (None, "Unknown") else None)
        or c.get("manufacturer")
        or fb_mfr
        or "Unknown-NIC"
    )

    # Category: AI's normalized_type beats Omada's "Others" default for
    # unknown devices, but Fingerbank's specific device class still wins.
    cat = (
        (fb_cache.get("device", {}).get("name") if fb_cache else None)
        or (ai_type if ai_type and ai_type != "Other" else None)
        or c.get("deviceCategory")
        or c.get("deviceType")
        or "Others"
    )

    return {
        "name":  name,
        "host":  host,
        "cat":   cat,
        "os":    os_name,
        "type":  type_name,
        "vdr":   vendor,
        "mac":   c.get("mac", ""),
        "ip":    c.get("ip", ""),
        "notes": (notes or "Unknown"),
        "_ai":   ai_cache,
    }


# ---------------------------------------------------------------------------
# Omada Open API client — token cached across requests, refreshed on expiry
# ---------------------------------------------------------------------------
class OmadaClient:
    """Lazy, thread-safe Open API client. One instance per process."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.omada_id: str | None = None
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.token_expires_at: float = 0.0
        self.site_id: str | None = None
        self.site_name: str | None = None
        self.session = requests.Session()
        self.session.verify = OMADA_VERIFY_TLS

    # ---- low-level auth ---------------------------------------------------
    def _fetch_omada_id(self) -> str:
        r = self.session.get(f"{OMADA_URL}/api/info", timeout=5)
        r.raise_for_status()
        body = r.json()
        if body.get("errorCode") != 0:
            raise RuntimeError(f"/api/info failed: {body}")
        return body["result"]["omadacId"]

    def _request_token(self) -> None:
        if self.omada_id is None:
            self.omada_id = self._fetch_omada_id()
        r = self.session.post(
            f"{OMADA_URL}/openapi/authorize/token",
            params={"grant_type": "client_credentials"},
            json={
                "omadacId": self.omada_id,
                "client_id": OMADA_CLIENT_ID,
                "client_secret": OMADA_CLIENT_SECRET,
            },
            timeout=10,
        )
        r.raise_for_status()
        body = r.json()
        if body.get("errorCode") != 0:
            raise RuntimeError(f"token request failed: {body}")
        result = body["result"]
        self.access_token = result["accessToken"]
        self.refresh_token = result.get("refreshToken")
        # Re-auth 60s before real expiry to be safe.
        self.token_expires_at = time.monotonic() + int(result["expiresIn"]) - 60
        log.info(
            "Got new access token (expires in %ss)", result.get("expiresIn")
        )

    def _ensure_token(self) -> None:
        with self._lock:
            if (
                self.access_token is None
                or time.monotonic() >= self.token_expires_at
            ):
                self._request_token()

    def _ensure_site(self) -> None:
        if self.site_id is not None:
            return
        sites = self._request("GET", "/sites", params={"page": 1, "pageSize": 100})
        data = sites["result"]["data"]
        if not data:
            raise RuntimeError("No sites visible to this application")
        # First site — adjust if you ever have more than one.
        self.site_id = data[0]["siteId"]
        self.site_name = data[0]["name"]
        log.info("Using site %s (%s)", self.site_name, self.site_id)

    # ---- request wrapper --------------------------------------------------
    def _request(self, method: str, path: str, **kwargs) -> dict:
        self._ensure_token()
        url = f"{OMADA_URL}/openapi/v1/{self.omada_id}{path}"
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"AccessToken={self.access_token}"
        headers.setdefault("Content-Type", "application/json")
        r = self.session.request(method, url, headers=headers, timeout=15, **kwargs)
        # Token may have been invalidated server-side. Retry once.
        if r.status_code == 401 or (
            r.headers.get("content-type", "").startswith("application/json")
            and r.json().get("errorCode") in (-44112, -44113)
        ):
            log.warning("Token rejected, refreshing and retrying once")
            with self._lock:
                self._request_token()
            headers["Authorization"] = f"AccessToken={self.access_token}"
            r = self.session.request(
                method, url, headers=headers, timeout=15, **kwargs
            )
        r.raise_for_status()
        return r.json()

    # ---- public surface ---------------------------------------------------
    def list_clients(self) -> list[dict]:
        self._ensure_site()
        body = self._request(
            "GET",
            f"/sites/{self.site_id}/clients",
            params={"page": 1, "pageSize": 1000},
        )
        if body.get("errorCode") != 0:
            raise RuntimeError(f"list_clients failed: {body}")
        return body["result"].get("data", [])

    def list_aps(self) -> list[dict]:
        """List the site's network devices (APs, switches, gateways). Omada's
        Open API exposes these under /devices. Returns whatever the controller
        gives; callers pick out mac/name/type."""
        self._ensure_site()
        body = self._request(
            "GET",
            f"/sites/{self.site_id}/devices",
            params={"page": 1, "pageSize": 1000},
        )
        if body.get("errorCode") != 0:
            raise RuntimeError(f"list_aps failed: {body}")
        result = body.get("result", {})
        # Some controllers return a paged {data: [...]}, others a bare list.
        if isinstance(result, dict):
            return result.get("data", [])
        return result if isinstance(result, list) else []

    def rename_client(self, mac: str, name: str) -> dict:
        """Best guess at the Open API rename path. Verify at /doc.html on your controller."""
        self._ensure_site()
        mac_dash = mac.replace(":", "-").upper()
        # Path #1: object PATCH with name in body (common Open API convention)
        try:
            body = self._request(
                "PATCH",
                f"/sites/{self.site_id}/clients/{mac_dash}",
                json={"name": name[:128]},
            )
            if body.get("errorCode") == 0:
                return body
            log.warning("Object PATCH rename returned %s, trying /name subpath", body)
        except requests.HTTPError as exc:
            log.warning("Object PATCH rename HTTPError %s, trying /name subpath", exc)

        # Path #2: /name subpath (matches the Web API style)
        return self._request(
            "PATCH",
            f"/sites/{self.site_id}/clients/{mac_dash}/name",
            json={"name": name[:128]},
        )


omada = OmadaClient()


# ---------------------------------------------------------------------------
# AP name cache — maps an AP MAC (dash-upper) to its Omada-configured name.
# Flow logs reference APs by MAC; this lets us show "Garage AP" instead of a
# bare MAC in graphs, the briefing, and the chatbot. AP names rarely change,
# so we cache for a while and refresh lazily.
# ---------------------------------------------------------------------------
_ap_name_cache: dict[str, str] = {}
_ap_cache_ts = 0.0
_ap_cache_lock = threading.Lock()
_AP_CACHE_TTL = 600  # seconds


def get_ap_names(force: bool = False) -> dict[str, str]:
    """Return {AP_MAC_DASH_UPPER: name}. Cached; refreshes every _AP_CACHE_TTL.
    Best-effort: on any API error, returns whatever we last had (possibly {})."""
    global _ap_cache_ts
    now = time.time()
    if not force and _ap_name_cache and (now - _ap_cache_ts) < _AP_CACHE_TTL:
        return _ap_name_cache
    with _ap_cache_lock:
        if not force and _ap_name_cache and (time.time() - _ap_cache_ts) < _AP_CACHE_TTL:
            return _ap_name_cache
        try:
            devices = omada.list_aps()
            fresh = {}
            for d in devices:
                mac = (d.get("mac") or d.get("deviceMac") or "").upper().replace(":", "-")
                name = d.get("name") or d.get("deviceName")
                if mac:
                    fresh[mac] = name or "Access Point"
            if fresh:
                _ap_name_cache.clear()
                _ap_name_cache.update(fresh)
            _ap_cache_ts = time.time()
        except Exception as exc:
            log.warning("get_ap_names: could not refresh AP list: %s", exc)
    return _ap_name_cache


def resolve_ap(mac: str) -> str | None:
    """AP MAC → name, or None if unknown."""
    if not mac:
        return None
    return get_ap_names().get(mac.upper().replace(":", "-"))



def get_nested(data: dict, path: str, default: str = "Unknown") -> str:
    cur = data
    try:
        for key in path.split("."):
            if isinstance(cur, list):
                cur = cur[int(key)]
            elif isinstance(cur, dict):
                cur = cur.get(key)
            else:
                return default
            if cur is None:
                return default
        return str(cur)
    except (KeyError, IndexError, ValueError, TypeError):
        return default


KNOWN_TAGS = {"name", "host", "cat", "os", "vdr", "mac", "ip", "type", "notes"}


def shell_escape(s: str) -> str:
    """Single-quote a string for safe embedding in a bash command."""
    return "'" + str(s).replace("'", "'\\''") + "'"


def build_curl_commands(mac: str, proposed_name: str) -> dict:
    """curl equivalents of what the Push button does — for debugging the
    rename endpoint shape (Omada Open API v1 docs are vague on this)."""
    mac_dash = mac.replace(":", "-").upper()
    site_id = omada.site_id or "<SITE_ID>"
    omada_id = omada.omada_id or "<OMADA_ID>"

    auth_body = json.dumps({
        "omadacId": omada_id,
        "client_id": OMADA_CLIENT_ID,
        "client_secret": OMADA_CLIENT_SECRET,
    })
    rename_body = json.dumps({"name": proposed_name[:128]})
    insecure = "-sk" if not OMADA_VERIFY_TLS else "-s"

    token_cmd = (
        f"TOKEN=$(curl {insecure} -X POST \\\n"
        f"  {shell_escape(OMADA_URL + '/openapi/authorize/token?grant_type=client_credentials')} \\\n"
        f"  -H 'Content-Type: application/json' \\\n"
        f"  -d {shell_escape(auth_body)} \\\n"
        f"  | jq -r .result.accessToken)\n"
        f"echo \"Token: $TOKEN\""
    )

    inspect_cmd = (
        f"curl {insecure} \\\n"
        f"  {shell_escape(f'{OMADA_URL}/openapi/v1/{omada_id}/sites/{site_id}/clients?page=1&pageSize=1000')} \\\n"
        f"  -H \"Authorization: AccessToken=$TOKEN\" \\\n"
        f"  | jq '.result.data[] | select(.mac==\"{mac_dash}\")'"
    )

    rename_cmd = (
        f"curl {insecure} -X PATCH \\\n"
        f"  {shell_escape(f'{OMADA_URL}/openapi/v1/{omada_id}/sites/{site_id}/clients/{mac_dash}')} \\\n"
        f"  -H \"Authorization: AccessToken=$TOKEN\" \\\n"
        f"  -H 'Content-Type: application/json' \\\n"
        f"  -d {shell_escape(rename_body)}"
    )

    rename_alt_cmd = (
        f"curl {insecure} -X PATCH \\\n"
        f"  {shell_escape(f'{OMADA_URL}/openapi/v1/{omada_id}/sites/{site_id}/clients/{mac_dash}/name')} \\\n"
        f"  -H \"Authorization: AccessToken=$TOKEN\" \\\n"
        f"  -H 'Content-Type: application/json' \\\n"
        f"  -d {shell_escape(rename_body)}"
    )

    return {
        "token": token_cmd,
        "inspect": inspect_cmd,
        "rename": rename_cmd,
        "rename_alt": rename_alt_cmd,
    }


def render_template_name(template: str, ctx: dict, fb_cache: dict) -> str:
    """Substitute known tags, then any fingerbank field via dotted path."""
    out = template
    for tag in KNOWN_TAGS:
        out = out.replace("{" + tag + "}", str(ctx.get(tag, "Unknown")))
    # AI tokens: {ai.suggested_label}, {ai.manufacturer}, etc.
    ai_data = ctx.get("_ai") or {}
    for tag in re.findall(r"\{ai\.([^{}]+)\}", out):
        out = out.replace("{ai." + tag + "}", str(ai_data.get(tag, "Unknown")))
    # Anything else: try it as a fingerbank dotted path.
    for tag in re.findall(r"\{([^{}]+)\}", out):
        out = out.replace("{" + tag + "}", get_nested(fb_cache, tag))
    return out


# ---------------------------------------------------------------------------
# Gemini AI device identification
# ---------------------------------------------------------------------------
GEMINI_OS_ENUM = [
    "iOS", "Android", "macOS", "Windows", "Linux", "ChromeOS",
    "Embedded", "RTOS", "Unknown",
]
GEMINI_TYPE_ENUM = [
    "PC", "Phone", "Tablet", "Camera", "TV", "Console", "Printer",
    "Router", "Server", "IOT", "Speaker", "Watch", "Vehicle",
    "Appliance", "Other",
]

GEMINI_SCHEMA = {
    "type": "object",
    "properties": {
        "summary":         {"type": "string"},
        # Concise ≤10-word description for surfacing as a table column. Plain
        # English, no jargon, no bullets — reads like "Apple TV 4K streaming
        # box in the living room" rather than "Identified device".
        "brief_description": {"type": "string"},
        "manufacturer":    {"type": "string"},
        "product_type":    {"type": "string"},
        # Structured fields used by the standard naming template.
        "short_name":      {"type": "string"},  # <=30 chars, no spaces
        "normalized_os":   {"type": "string", "enum": GEMINI_OS_ENUM},
        "normalized_type": {"type": "string", "enum": GEMINI_TYPE_ENUM},
        # Backwards-compat: free-form label and rationale.
        "suggested_label": {"type": "string"},
        "confidence":      {"type": "string", "enum": ["low", "medium", "high"]},
        "reasoning":       {"type": "string"},
        "security_notes":  {"type": "string"},
    },
    "required": [
        "summary", "brief_description", "manufacturer", "product_type",
        "short_name", "normalized_os", "normalized_type",
        "suggested_label", "confidence", "reasoning",
    ],
}


def _build_gemini_prompt(c: dict, fb_cache: dict, notes: str | None = None,
                          dhcp_fp: str | None = None,
                          dhcp_vendor: str | None = None,
                          mdns_data: dict | None = None) -> str:
    """Compress what we know about a client into a prompt."""
    fb_summary = "no Fingerbank data"
    if fb_cache:
        dev = fb_cache.get("device", {}) or {}
        man = fb_cache.get("manufacturer", {}) or {}
        parts = []
        if dev.get("name"):
            parts.append(f"device={dev['name']}")
        if dev.get("parents"):
            chain = " > ".join(p.get("name", "?") for p in dev["parents"])
            parts.append(f"hierarchy={chain}")
        if man.get("name"):
            parts.append(f"oui_manufacturer={man['name']}")
        fb_summary = "; ".join(parts) or "Fingerbank returned empty"

    lines = [
        "You are identifying an unknown device on a private network. Use the",
        "data below to figure out what device this most likely is. Be specific",
        "where the evidence supports it (manufacturer + product family/model),",
        "and honest about confidence when it doesn't.",
        "",
        f"MAC address:      {c.get('mac', '?')}",
        f"DHCP hostname:    {c.get('hostName') or '(none)'}",
        f"Current label:    {c.get('name') or '(none)'}",
        f"IP address:       {c.get('ip', '?')}",
        f"Connection type:  {'wireless' if c.get('wireless') else 'wired'}",
        f"SSID:             {c.get('ssid', '(n/a)')}",
        f"AP / switch:      {c.get('apName') or c.get('switchName') or '(n/a)'}",
        f"Omada OS guess:   {c.get('osName') or c.get('os') or '(none)'}",
        f"Omada type guess: {c.get('deviceType') or '(none)'}",
        f"Omada category:   {c.get('deviceCategory') or '(none)'}",
        f"Omada vendor:     {c.get('vendor') or c.get('manufacturer') or '(none)'}",
        f"DHCP fingerprint: {dhcp_fp or '(not captured)'}",
        f"DHCP vendor cls:  {dhcp_vendor or '(none)'}",
        f"Fingerbank:       {fb_summary}",
    ]
    if dhcp_fp:
        lines.append(
            "  (DHCP fingerprint = option 55 parameter request list. Order and"
            " content are strong OS signals; vendor class often names the OS"
            " or device class verbatim — e.g. 'MSFT 5.0', 'android-dhcp-14',"
            " 'dhcpcd-9.4.1:Linux'.)"
        )

    # mDNS section — devices voluntarily announce what services they expose,
    # which is a very high-signal identification feature (essentially the
    # device telling you what it is). Include service types, useful TXT
    # records, and human-readable instance names if present.
    if mdns_data:
        svcs = mdns_data.get("services") or []
        txt = mdns_data.get("txt") or {}
        instances = mdns_data.get("instance_names") or []
        if svcs or txt or instances:
            lines.append("")
            lines.append("mDNS / Bonjour observations (the device is announcing these):")
            if svcs:
                lines.append(f"  services: {', '.join(svcs)}")
                lines.append(
                    "  (Service types are diagnostic of device role. Examples:"
                    " _hap._tcp = HomeKit accessory; _googlecast._tcp = Chromecast;"
                    " _airplay._tcp = AirPlay receiver; _spotify-connect._tcp = Sonos"
                    " or smart speaker; _printer._tcp + _ipp._tcp = printer;"
                    " _companion-link._tcp = Apple device; _hue._tcp = Hue bridge;"
                    " _amzn-wplay._tcp = Fire TV / Echo Show.)"
                )
            if txt:
                # Pick the most useful TXT keys first — md (model), fn (friendly
                # name), vers/sw (firmware), ic (icon-implies-vendor), srcvers.
                priority = ["md", "fn", "vers", "sw", "srcvers", "model", "manufacturer"]
                shown: list[str] = []
                for k in priority:
                    if k in txt:
                        shown.append(f"{k}={txt[k]}")
                # Then any other TXT keys, capped to keep prompt tight.
                for k, v in txt.items():
                    if k not in priority and len(shown) < 10:
                        shown.append(f"{k}={v}")
                if shown:
                    lines.append(f"  txt:      {'; '.join(shown)}")
                    lines.append(
                        "  (TXT records often carry the exact model: md=AppleTV5,3,"
                        " md=Chromecast, md=HomePodMini, etc. Trust these.)"
                    )
            if instances:
                # Cap to first 5 to keep prompt readable.
                shown_instances = instances[:5]
                lines.append(f"  instances: {', '.join(repr(i) for i in shown_instances)}")
                if len(instances) > 5:
                    lines.append(f"             ... and {len(instances) - 5} more")

    if notes:
        lines.extend([
            "",
            "Owner's notes about this device (TRUST THESE — the network owner",
            "knows their own gear better than any guess from MAC/fingerprint data):",
            f"  {notes}",
        ])
    lines.extend([
        "",
        "Required output (structured JSON, fields will be enforced by schema):",
        "  summary: 1-2 sentence explanation of what this device is and what",
        "           it's used for. Free-form, can be detailed.",
        "  brief_description: a punchy ≤10-word plain-English description that",
        "           would make sense as a table-column entry. Read it back to",
        "           yourself — does it tell a network admin at a glance what",
        "           the device is and what it does? Examples:",
        "             'Apple TV 4K — living room AirPlay/HomeKit hub'",
        "             'Reolink IP camera — front gate, PoE-powered'",
        "             'ESP32-based smart plug — kitchen, Tasmota firmware'",
        "             'Proxmox VM — Home Assistant container'",
        "           Avoid filler like 'identified device' or 'unknown gadget'.",
        "           Lead with the role/purpose if known, manufacturer second.",
        "  short_name: 8-30 chars, no spaces, hyphens or CamelCase, descriptive",
        "              and unique-ish across a home network. Examples:",
        "              'KlipperVoron', 'DadsIPhone16', 'FrontGateCam',",
        "              'LivingRoomTV', 'OfficePrinter', 'GuestLaptop'.",
        f"  normalized_os: one of {GEMINI_OS_ENUM}.",
        f"                 Use 'Embedded' for IoT/firmware, 'RTOS' for",
        f"                 microcontroller-class, 'Unknown' only as last resort.",
        f"  normalized_type: one of {GEMINI_TYPE_ENUM}.",
        "                  'Server' covers home servers, NAS, RPi running",
        "                  services, Klipper/Frigate/Home Assistant hosts.",
        "                  'IOT' covers light bulbs, sensors, hubs, switches.",
        "                  'Camera' covers security/IP cameras.",
        "  suggested_label: a longer free-form label (legacy, < 40 chars).",
        "  confidence: low/medium/high — be honest, don't bluff on a hunch.",
        "  reasoning: 1-2 sentences explaining what evidence drove the answer.",
        "  security_notes: optional, only flag if the device has obvious risks",
        "                  (default creds, EOL firmware, surveillance concerns).",
        "",
        "If the owner's notes explicitly state the device's role, the",
        "short_name and normalized_type MUST reflect that role, even if other",
        "evidence (hostname, OUI) would suggest otherwise.",
    ])
    return "\n".join(lines)


def get_active_gemini_model() -> str:
    """Read configured model from DB, fall back to env default."""
    row = GlobalSetting.query.first()
    if row and row.gemini_model and row.gemini_model in GEMINI_MODEL_IDS:
        return row.gemini_model
    return GEMINI_MODEL


def analyze_with_gemini(c: dict, fb_cache: dict, notes: str | None = None,
                         model: str | None = None,
                         dhcp_fp: str | None = None,
                         dhcp_vendor: str | None = None,
                         mdns_data: dict | None = None) -> dict:
    """One-shot Gemini call. Raises on HTTP/parse failure."""
    model = model or get_active_gemini_model()
    prompt = _build_gemini_prompt(c, fb_cache, notes, dhcp_fp, dhcp_vendor, mdns_data)
    payload = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": GEMINI_SCHEMA,
            "temperature": 0.3,
        },
    }
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent"
    )
    r = requests.post(
        url,
        params={"key": GEMINI_API_KEY},
        json=payload,
        timeout=60,
    )
    r.raise_for_status()
    body = r.json()
    try:
        text = body["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError) as exc:
        raise RuntimeError(f"Unexpected Gemini response shape: {body}") from exc
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Gemini returned non-JSON: {text!r}") from exc
    parsed["_model"] = model
    return parsed


# ---------------------------------------------------------------------------
# Cluster-aware harmonization (Option C)
# ---------------------------------------------------------------------------
HARMONIZE_SCHEMA = {
    "type": "object",
    "properties": {
        "proposals": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "mac": {"type": "string"},
                    "proposed_short_name": {"type": "string"},
                    "reasoning": {"type": "string"},
                },
                "required": ["mac", "proposed_short_name"],
            }
        }
    },
    "required": ["proposals"],
}

# Common corporate suffixes to strip when normalizing a manufacturer string
# into a stable cluster key. Order matters — longer / more specific first.
_MFR_SUFFIXES = [
    " co., ltd.", " co. ltd.", " co. ltd", " co ltd",
    ", inc.", " inc.", " inc",
    " technology co", " technologies", " technology", " tech.",
    " corporation", " corp.", " corp",
    " ltd.", " ltd", " limited",
    " gmbh", " ag", " sas", " bv",
]
# Location/geography words that often prefix Chinese OEM names.
_MFR_LOCATIONS = {
    "shenzhen", "beijing", "hangzhou", "zhejiang", "shanghai",
    "guangdong", "taiwan", "guangzhou", "ningbo", "xiamen",
}


def normalize_manufacturer(s: str | None) -> str:
    """Reduce a manufacturer string to a stable cluster key.

    Examples:
      "Zhejiang Dahua Technology Co., Ltd." -> "dahua"
      "Dahua Technology"                    -> "dahua"
      "Dahua"                               -> "dahua"
      "TP-Link Corporation"                 -> "tp-link"
    """
    if not s:
        return ""
    s = s.lower().strip()
    for suffix in _MFR_SUFFIXES:
        if s.endswith(suffix):
            s = s[:-len(suffix)].strip()
    words = [w for w in s.split() if w not in _MFR_LOCATIONS]
    if not words:
        return s
    return words[0]


def cluster_devices_for_harmonization(raw_clients: list, settings_by_mac: dict) -> dict:
    """Group AI-named devices into clusters where harmonization would help.

    Returns dict {cluster_key: [member_dicts]}, only including clusters with
    2+ members. A device must already have an AI short_name to participate —
    harmonization is for fixing AI output, not generating it from scratch.
    """
    clusters: dict[str, list] = {}
    for c in raw_clients:
        mac = c.get("mac")
        if not mac:
            continue
        setting = settings_by_mac.get(mac)
        if not setting or not setting.ai_analysis:
            continue
        try:
            ai_data = json.loads(setting.ai_analysis)
        except json.JSONDecodeError:
            continue
        short_name = ai_data.get("short_name")
        if not short_name:
            continue
        mfr = ai_data.get("manufacturer") or c.get("vendor") or c.get("manufacturer") or ""
        key = normalize_manufacturer(mfr)
        if not key:
            continue
        clusters.setdefault(key, []).append({
            "mac": mac,
            "current_short_name": short_name,
            "ai_data": ai_data,
            "hostname": c.get("hostName") or "",
            "omada_name": c.get("name") or "",
            "notes": setting.notes or None,
            "ip": c.get("ip") or "",
            "dhcp_vendor_class": setting.dhcp_vendor_class or None,
        })
    return {k: v for k, v in clusters.items() if len(v) >= 2}


def _build_harmonize_prompt(cluster_key: str, members: list[dict]) -> str:
    """Compose the Gemini prompt for harmonizing one cluster."""
    lines = []
    for i, m in enumerate(members, 1):
        ai = m["ai_data"]
        parts = [
            f"MAC={m['mac']}",
            f'current_short_name="{m["current_short_name"]}"',
            f'hostname="{m["hostname"]}"',
            f'type={ai.get("normalized_type", "?")}',
            f'os={ai.get("normalized_os", "?")}',
        ]
        if m.get("dhcp_vendor_class"):
            parts.append(f'dhcp_vendor="{m["dhcp_vendor_class"]}"')
        if m.get("notes"):
            parts.append(f'notes="{m["notes"]}"')
        lines.append(f"{i}. " + " ".join(parts))

    return (
        "You are reviewing a cluster of related devices on a private network "
        "and proposing harmonized short_names that share a consistent style.\n\n"
        f"Cluster: {cluster_key.title()} ({len(members)} devices)\n\n"
        "Current state of each device:\n"
        + "\n".join(lines)
        + "\n\n"
        "Goals:\n"
        "1. Use a single consistent prefix for the whole cluster "
        "(e.g. \"DahuaCam-\", \"ShellySwitch-\"). The prefix should be the "
        "canonical short form of the manufacturer name.\n"
        "2. Distinguish individual devices with meaningful suffixes, in order "
        "of preference: location from notes, then model variant from hostname/"
        "dhcp_vendor, then a 4-char MAC tail as last resort.\n"
        "3. Keep each short_name ≤ 30 chars total, no spaces (use - or _ or "
        "CamelCase). Allowed characters: letters, digits, -, _.\n"
        "4. Preserve meaningful detail from existing names where possible. "
        "If an existing name is good, propose the same name back.\n"
        "5. Fix typos in existing names (e.g. \"DahualPCamera\" → \"DahuaIPCam\").\n"
        "6. Do NOT produce duplicate short_names within the cluster.\n\n"
        "Return a JSON object with a \"proposals\" array, one entry per device, "
        "in the same order as the input list."
    )


def harmonize_cluster_with_gemini(cluster_key: str, members: list[dict],
                                    model: str | None = None) -> list[dict]:
    """Single Gemini call that harmonizes a whole cluster.
    Returns list of proposal dicts: [{mac, proposed_short_name, reasoning}, ...]
    """
    model = model or get_active_gemini_model()
    prompt = _build_harmonize_prompt(cluster_key, members)
    payload = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": HARMONIZE_SCHEMA,
            "temperature": 0.2,  # lower temp for batch consistency
        },
    }
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent"
    )
    r = requests.post(url, params={"key": GEMINI_API_KEY}, json=payload, timeout=90)
    r.raise_for_status()
    body = r.json()
    try:
        text = body["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError) as exc:
        raise RuntimeError(f"Unexpected Gemini response shape: {body}") from exc
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Gemini returned non-JSON: {text!r}") from exc
    return parsed.get("proposals", [])


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/settings", methods=["GET", "POST"])
def handle_settings():
    setting = GlobalSetting.query.first()
    if request.method == "POST":
        data = request.json or {}
        tpl = data.get("template")
        model = data.get("gemini_model")

        if setting is None:
            setting = GlobalSetting()
            db.session.add(setting)
        if tpl is not None:
            setting.naming_template = tpl or DEFAULT_TEMPLATE
        if model is not None:
            if model and model not in GEMINI_MODEL_IDS:
                return jsonify({"error": f"unknown model: {model}"}), 400
            setting.gemini_model = model or None  # empty = revert to env default
        db.session.commit()
        return jsonify({
            "status": "success",
            "template": setting.naming_template,
            "gemini_model": setting.gemini_model or GEMINI_MODEL,
        })

    return jsonify({
        "template": setting.naming_template if setting else DEFAULT_TEMPLATE,
        "gemini_model": (setting.gemini_model if setting and setting.gemini_model else GEMINI_MODEL),
        "gemini_models": GEMINI_MODELS,
    })


def _mask_secret(value: str | None) -> str:
    """Return a masked version of a secret showing only the last 4 chars.
    Empty/None becomes ''. Used in /api/config GET so clients see something
    recognizable without exposing the full secret in logs/screenshots."""
    if not value:
        return ""
    if len(value) <= 4:
        return "•" * len(value)
    return "•" * (len(value) - 4) + value[-4:]


@app.route("/api/config", methods=["GET", "PUT"])
def handle_config():
    """Read or write the credential bundle. Secrets are masked in GET
    responses unless `?reveal=1` is passed (useful when editing). PUT
    accepts any subset of fields and reloads the app config in-place;
    no restart required.

    Request body keys mirror the GlobalSetting columns:
      omada_url, omada_client_id, omada_client_secret,
      gemini_api_key, fingerbank_api_key

    Empty string clears the override and falls back to ENV default."""
    setting = GlobalSetting.query.first()

    if request.method == "PUT":
        data = request.json or {}
        if setting is None:
            setting = GlobalSetting()
            db.session.add(setting)
        for field in ("omada_url", "omada_client_id", "omada_client_secret",
                      "gemini_api_key", "fingerbank_api_key"):
            if field in data:
                val = data[field]
                # Treat the masked placeholder as "no change" — saves us from
                # asking the UI to track which fields were actually edited.
                if isinstance(val, str) and val.startswith("•"):
                    continue
                setattr(setting, field, val or None)
        db.session.commit()
        reload_app_config()
        log.info("Config updated (omada/gemini/fingerbank credentials)")
        return jsonify({"status": "success"})

    # GET: return current effective config + indication of which values are
    # set in DB vs falling back to ENV.
    reveal = request.args.get("reveal") == "1"
    fields = {
        "omada_url": OMADA_URL,
        "omada_client_id": OMADA_CLIENT_ID,
        "omada_client_secret": OMADA_CLIENT_SECRET,
        "gemini_api_key": GEMINI_API_KEY,
        "fingerbank_api_key": FINGERBANK_API_KEY,
    }
    secret_fields = {"omada_client_secret", "gemini_api_key", "fingerbank_api_key"}
    out = {}
    for k, v in fields.items():
        if k in secret_fields and not reveal:
            out[k] = _mask_secret(v)
        else:
            out[k] = v or ""
    # Tell the UI which fields are DB-overridden vs ENV-defaulted
    out["_sources"] = {}
    if setting:
        for k in fields:
            out["_sources"][k] = "db" if getattr(setting, k, None) else "env"
    else:
        out["_sources"] = {k: "env" for k in fields}
    return jsonify(out)


@app.route("/api/config/test_omada", methods=["POST"])
def test_omada_config():
    """Try fetching an Omada access token with the currently-stored
    credentials. Returns 200 if successful, 502 with error detail otherwise."""
    try:
        # Build a fresh client so we exercise the *current* config rather
        # than reusing a token cached against the previous credentials.
        probe = OmadaClient()
        probe._request_token()
        if not probe.access_token:
            raise RuntimeError("No access token returned")
        return jsonify({"status": "ok",
                        "token_preview": probe.access_token[:8] + "…",
                        "omada_url": OMADA_URL})
    except Exception as exc:
        log.exception("Omada credential test failed")
        return jsonify({"status": "error", "error": str(exc)}), 502


@app.route("/api/config/test_gemini", methods=["POST"])
def test_gemini_config():
    """Verify the Gemini key by listing models. Cheap call, no token spend."""
    if not GEMINI_API_KEY:
        return jsonify({"status": "error", "error": "No Gemini API key configured"}), 400
    try:
        r = requests.get(
            "https://generativelanguage.googleapis.com/v1beta/models",
            params={"key": GEMINI_API_KEY},
            timeout=15,
        )
        r.raise_for_status()
        models = r.json().get("models", [])
        return jsonify({"status": "ok", "models_visible": len(models)})
    except requests.HTTPError as exc:
        body = exc.response.text if exc.response is not None else str(exc)
        return jsonify({"status": "error", "error": body[:200]}), 502
    except Exception as exc:
        return jsonify({"status": "error", "error": str(exc)}), 502


@app.route("/api/clients")
def get_clients():
    """READ-ONLY for Omada side, but updates DB with first/last_seen tracking."""
    try:
        raw_clients = omada.list_clients()
    except Exception as exc:
        log.exception("list_clients failed")
        return jsonify({"error": str(exc), "clients": []}), 502

    tpl_row = GlobalSetting.query.first()
    template = tpl_row.naming_template if tpl_row else DEFAULT_TEMPLATE

    now_iso = iso_now()
    out = []
    dirty = False  # whether we modified the DB in this loop
    for c in raw_clients:
        mac = c.get("mac", "")
        setting = get_setting(mac)
        # Always upsert first_seen/last_seen so the home network "log" stays current.
        if setting is None:
            setting = DeviceSetting(
                mac=mac, auto_sync=False,
                first_seen=now_iso, last_seen=now_iso,
            )
            db.session.add(setting)
            dirty = True
        else:
            if not setting.first_seen:
                setting.first_seen = now_iso
                dirty = True
            if setting.last_seen != now_iso:
                setting.last_seen = now_iso
                dirty = True

        fb_cache: dict = {}
        ai_cache: dict = {}
        if setting.fingerbank_cache:
            try:
                fb_cache = json.loads(setting.fingerbank_cache)
            except json.JSONDecodeError:
                fb_cache = {}
        elif setting.dhcp_fingerprint:
            # Fingerprint already in DB but never queried Fingerbank — fire an
            # async lookup. Result will appear in the next poll's response.
            # Dedup by MAC inside _async_fingerbank_lookup handles repeated polls.
            _async_fingerbank_lookup(setting.mac)
        if setting.ai_analysis:
            try:
                ai_cache = json.loads(setting.ai_analysis)
            except json.JSONDecodeError:
                ai_cache = {}
        notes = setting.notes or ""

        ctx = build_template_ctx(c, fb_cache, ai_cache, notes)
        proposed = render_template_name(template, ctx, fb_cache)[:128]

        identified = bool(notes) or bool(ai_cache)
        is_new = (
            setting.first_seen == now_iso  # just discovered this poll
            or is_recent(setting.first_seen, days=7)
        )

        c["proposed_name"] = proposed
        c["host_name_resolved"] = ctx["host"]
        # Raw DHCP hostname only, no fallback to Omada display name. The HOSTNAME
        # column in the UI uses this; the naming-template engine still uses
        # host_name_resolved (which falls back to ensure {host} always renders).
        c["dhcp_hostname"] = c.get("hostName") or ""
        c["oui_vendor"] = ctx["vdr"]
        c["resolved_name"] = ctx["name"]
        c["resolved_os"]   = ctx["os"]
        c["resolved_type"] = ctx["type"]
        c["auto_sync"] = bool(setting.auto_sync)
        c["fb_data"] = fb_cache
        c["ai_data"] = ai_cache
        c["ai_analyzed_at"] = setting.ai_analyzed_at
        c["last_synced_name"] = setting.last_synced_name
        c["notes"] = notes
        c["first_seen"] = setting.first_seen
        c["last_seen"] = setting.last_seen
        c["dhcp_fingerprint"] = setting.dhcp_fingerprint
        c["dhcp_vendor_class"] = setting.dhcp_vendor_class
        c["dhcp_captured_at"] = setting.dhcp_captured_at
        # mDNS observations (services announced, TXT records, instance names)
        try:
            c["mdns_data"] = (json.loads(setting.mdns_data)
                               if setting.mdns_data else None)
        except (json.JSONDecodeError, TypeError):
            c["mdns_data"] = None
        c["mdns_captured_at"] = setting.mdns_captured_at
        c["identified"] = identified
        c["is_new"] = is_new
        c["curl"] = build_curl_commands(mac, proposed)
        out.append(c)

    if dirty:
        db.session.commit()

    return jsonify({"clients": out, "site": omada.site_name})


@app.route("/api/raw_client/<mac>")
def raw_client(mac):
    """Debug endpoint: dump the unfiltered Omada record for one MAC."""
    try:
        clients = omada.list_clients()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 502
    target = mac.upper().replace(":", "-")
    for c in clients:
        if c.get("mac", "").upper().replace(":", "-") == target:
            return jsonify(c)
    return jsonify({"error": "not found"}), 404


@app.route("/api/refresh_fingerbank", methods=["POST"])
def refresh_fingerbank():
    """Manual Fingerbank re-query. Same path used as the auto-lookup,
    but with two extra capabilities:
      - request body can pass `dhcp_fingerprint` / `dhcp_vendor` overrides
        (you can paste a fingerprint from elsewhere via the UI)
      - request body can pass `user_agent` for HTTP UA-based identification
    The auto path only ever uses what's in the DB; this manual path lets you
    experiment.
    """
    data = request.json or {}
    mac = data.get("mac")
    if not mac:
        return jsonify({"error": "mac required"}), 400

    setting = get_setting(mac)

    stored_fp = (setting.dhcp_fingerprint if setting else None)
    stored_vendor = (setting.dhcp_vendor_class if setting else None)

    # Manual overrides take priority over stored values.
    fingerprint = data.get("dhcp_fingerprint") or stored_fp
    vendor_class = data.get("dhcp_vendor") or stored_vendor
    user_agent = data.get("user_agent")

    fb_data = _fingerbank_lookup_sync(mac, fingerprint, vendor_class, user_agent)
    if fb_data is None:
        return jsonify({"error": "Fingerbank request failed (see server log)"}), 502

    fb_data["_request"] = {
        "fingerprint_used": fingerprint,
        "vendor_used": vendor_class,
        "fingerprint_source": (
            "manual" if data.get("dhcp_fingerprint")
            else "captured" if stored_fp else "none"
        ),
        "auto": False,
    }

    setting = setting or DeviceSetting(mac=mac, auto_sync=False)
    setting.fingerbank_cache = json.dumps(fb_data)
    db.session.add(setting)
    db.session.commit()
    return jsonify(fb_data)



@app.route("/api/ai_analyze", methods=["POST"])
def ai_analyze():
    """Ask Gemini to identify this device based on everything we know."""
    data = request.json or {}
    mac = data.get("mac")
    if not mac:
        return jsonify({"error": "mac required"}), 400

    # Pull the live client record from Omada so the prompt reflects current state.
    try:
        clients = omada.list_clients()
    except Exception as exc:
        return jsonify({"error": f"Omada fetch failed: {exc}"}), 502
    target_mac = mac.upper().replace(":", "-")
    client_rec = next(
        (c for c in clients if c.get("mac", "").upper().replace(":", "-") == target_mac),
        None,
    )
    if client_rec is None:
        return jsonify({"error": "client not found in current Omada list"}), 404

    setting = get_setting(mac)
    fb_cache: dict = {}
    notes: str | None = None
    dhcp_fp: str | None = None
    dhcp_vendor: str | None = None
    mdns_data: dict | None = None
    if setting:
        if setting.fingerbank_cache:
            try:
                fb_cache = json.loads(setting.fingerbank_cache)
            except json.JSONDecodeError:
                pass
        notes = setting.notes or None
        dhcp_fp = setting.dhcp_fingerprint
        dhcp_vendor = setting.dhcp_vendor_class
        if setting.mdns_data:
            try:
                mdns_data = json.loads(setting.mdns_data)
            except json.JSONDecodeError:
                pass

    try:
        analysis = analyze_with_gemini(
            client_rec, fb_cache,
            notes=notes, model=data.get("model"),
            dhcp_fp=dhcp_fp, dhcp_vendor=dhcp_vendor,
            mdns_data=mdns_data,
        )
    except requests.HTTPError as exc:
        body = exc.response.text if exc.response is not None else str(exc)
        log.error("Gemini HTTP error: %s", body)
        return jsonify({"error": f"Gemini API error: {body[:500]}"}), 502
    except Exception as exc:
        log.exception("Gemini analysis failed")
        return jsonify({"error": str(exc)}), 502

    setting = setting or DeviceSetting(mac=mac, auto_sync=False)
    setting.ai_analysis = json.dumps(analysis)
    setting.ai_analyzed_at = iso_now()
    db.session.add(setting)
    db.session.commit()
    return jsonify(analysis)


@app.route("/api/notes", methods=["POST"])
def update_notes():
    """Save user commentary for a device."""
    data = request.json or {}
    mac = data.get("mac")
    notes = (data.get("notes") or "").strip()
    if not mac:
        return jsonify({"error": "mac required"}), 400
    if len(notes) > 2000:
        return jsonify({"error": "notes too long (2000 char max)"}), 400
    setting = get_setting(mac)
    if not setting:
        setting = DeviceSetting(mac=mac, auto_sync=False, first_seen=iso_now())
        db.session.add(setting)
    setting.notes = notes or None
    db.session.commit()
    return jsonify({"status": "success", "mac": mac, "notes": setting.notes})


@app.route("/api/scan_unidentified", methods=["POST"])
def scan_unidentified():
    """Process up to `max` devices that lack an AI analysis. (Devices with
    user notes but no AI are still picked up — notes inform the prompt but
    only AI produces the structured short_name/normalized_os/normalized_type
    fields the standard naming template needs.)

    Designed to be called in a loop by the frontend with max=1, so each call
    is fast and progress is visible. Returns:
      { "analyzed": [{mac, summary, short_name, normalized_type, confidence}],
        "remaining": <count of still-needing-AI after this batch> }
    """
    data = request.json or {}
    try:
        batch_size = max(1, min(int(data.get("max", 1)), 5))
    except (TypeError, ValueError):
        batch_size = 1

    try:
        raw_clients = omada.list_clients()
    except Exception as exc:
        return jsonify({"error": f"Omada fetch failed: {exc}"}), 502

    # Build queue: devices without an AI analysis (regardless of notes).
    queue: list[dict] = []
    for c in raw_clients:
        mac = c.get("mac")
        if not mac:
            continue
        setting = get_setting(mac)
        if not (setting and setting.ai_analysis):
            queue.append(c)

    analyzed: list[dict] = []
    errors: list[dict] = []
    for client_rec in queue[:batch_size]:
        mac = client_rec["mac"]
        setting = get_setting(mac)
        fb_cache: dict = {}
        notes: str | None = None
        dhcp_fp: str | None = None
        dhcp_vendor: str | None = None
        mdns_data: dict | None = None
        if setting:
            if setting.fingerbank_cache:
                try:
                    fb_cache = json.loads(setting.fingerbank_cache)
                except json.JSONDecodeError:
                    pass
            notes = setting.notes or None
            dhcp_fp = setting.dhcp_fingerprint
            dhcp_vendor = setting.dhcp_vendor_class
            if setting.mdns_data:
                try:
                    mdns_data = json.loads(setting.mdns_data)
                except json.JSONDecodeError:
                    pass
        try:
            analysis = analyze_with_gemini(
                client_rec, fb_cache,
                notes=notes, dhcp_fp=dhcp_fp, dhcp_vendor=dhcp_vendor,
                mdns_data=mdns_data,
            )
        except Exception as exc:
            log.exception("scan: Gemini failed for %s", mac)
            errors.append({"mac": mac, "error": str(exc)})
            continue
        setting = setting or DeviceSetting(mac=mac, auto_sync=False, first_seen=iso_now())
        setting.ai_analysis = json.dumps(analysis)
        setting.ai_analyzed_at = iso_now()
        db.session.add(setting)
        analyzed.append({
            "mac": mac,
            "summary": analysis.get("summary"),
            "short_name": analysis.get("short_name"),
            "normalized_type": analysis.get("normalized_type"),
            "confidence": analysis.get("confidence"),
        })
    db.session.commit()

    return jsonify({
        "analyzed": analyzed,
        "errors": errors,
        "remaining": max(0, len(queue) - len(analyzed) - len(errors)),
        "total_needing_ai_before": len(queue),
        # Legacy key for backwards compat with existing frontend:
        "total_unidentified_before": len(queue),
    })


@app.route("/api/dhcp_status")
def dhcp_status():
    """Capture thread state + counts of devices with stored fingerprints."""
    fp_count = db.session.query(DeviceSetting).filter(
        DeviceSetting.dhcp_fingerprint.isnot(None)
    ).count()
    vc_count = db.session.query(DeviceSetting).filter(
        DeviceSetting.dhcp_vendor_class.isnot(None)
    ).count()
    return jsonify({
        **dhcp_capture.status(),
        "stored_fingerprints": fp_count,
        "stored_vendor_classes": vc_count,
        "enabled": DHCP_CAPTURE_ENABLED,
    })


@app.route("/api/syslog/status")
def syslog_status():
    """Listener state + stored-event stats for the dashboard banner."""
    total = db.session.query(SyslogEvent.id).count()
    # Quick breakdown by event_type for the summary.
    from sqlalchemy import func
    by_type = {
        (k or "unknown"): v for k, v in
        db.session.query(SyslogEvent.event_type, func.count(SyslogEvent.id))
        .group_by(SyslogEvent.event_type).all()
    }
    return jsonify({
        **syslog_capture.status(),
        "enabled": SYSLOG_ENABLED,
        "stored_events": total,
        "max_rows": SYSLOG_MAX_ROWS,
        "by_type": by_type,
        "drop_traffic_flow": _drop_traffic_flow,
        "dropped_flows": _syslog_dropped_count,
        "webhooks_received": _webhook_count,
    })


@app.route("/api/syslog/drop_flow", methods=["GET", "POST"])
def syslog_drop_flow():
    """Get or set whether traffic_flow events are dropped at ingest.
    POST body: {"enabled": true|false}. Persisted in GlobalSetting and applied
    live (no restart needed)."""
    global _drop_traffic_flow
    if request.method == "POST":
        enabled = bool((request.json or {}).get("enabled"))
        gs = GlobalSetting.query.first()
        if gs is None:
            gs = GlobalSetting()
            db.session.add(gs)
        gs.drop_traffic_flow = enabled
        db.session.commit()
        _drop_traffic_flow = enabled
        log.info("Syslog drop_traffic_flow set to %s", enabled)
    return jsonify({"enabled": _drop_traffic_flow,
                    "dropped_flows": _syslog_dropped_count})


@app.route("/api/aps")
def api_aps():
    """Diagnostic: the AP MAC→name map used to resolve infrastructure in
    graphs/briefing/chat. ?refresh=1 forces a re-fetch from Omada. If this
    returns an empty map, the controller's /devices endpoint didn't return
    usable data — check the path against your controller's /doc.html."""
    force = request.args.get("refresh") == "1"
    try:
        names = get_ap_names(force=force)
        return jsonify({"count": len(names), "aps": names,
                        "cache_age_seconds": round(time.time() - _ap_cache_ts, 1)})
    except Exception as exc:
        return jsonify({"error": str(exc), "count": 0, "aps": {}}), 502


# ---------------------------------------------------------------------------
# Webhook receiver — Omada controller notifications (Logs → Notifications →
# Webhook). These carry the real network-health events that syslog flow logs
# don't: device disconnected, WAN down, rogue DHCP, ARP/IP conflict, STP
# topology change, loop/storm detection, attack detection, etc. They land in
# the same SyslogEvent table so graphs / briefing / chatbot pick them up.
# ---------------------------------------------------------------------------

# Map keywords found in a webhook's text to our normalized event_type. Ordered
# most-specific first; first hit wins. Kept tolerant because Omada's exact JSON
# field names aren't documented — we match against the whole flattened text.
_WEBHOOK_EVENT_MAP = [
    ("rogue dhcp", "rogue_dhcp"),
    ("dhcp lease pool", "dhcp_pool_exhausted"),
    ("ip conflict", "ip_conflict"),
    ("arp conflict", "arp_conflict"),
    ("wan is down", "wan_down"),
    ("wan link backup", "wan_backup"),
    ("wan online detection", "wan_detection"),
    ("pppoe", "wan_pppoe_failed"),
    ("detected loop", "loop_detected"),
    ("loop detected", "loop_detected"),
    ("loop protect", "loop_detected"),
    ("storm", "storm_detected"),
    ("port blocked", "port_blocked"),
    ("stp topology", "stp_topology_changed"),
    ("detected attack", "attack_detected"),
    ("attack", "attack_detected"),
    ("flood attack", "attack_detected"),
    ("large ping", "attack_detected"),
    ("isolated", "ap_isolated"),
    ("desynchronized", "config_desync"),
    ("link down", "monitor_link_down"),
    ("link error", "monitor_link_error"),
    ("disconnected", "device_disconnected"),
    ("connected", "device_connected"),
    ("online", "online"),
    ("offline", "offline"),
    ("cpu utilization", "cpu_alert"),
    ("memory utilization", "memory_alert"),
]


def _classify_webhook(text: str) -> str:
    t = (text or "").lower()
    for needle, etype in _WEBHOOK_EVENT_MAP:
        if needle in t:
            return etype
    return "notification"


def _flatten_webhook(payload) -> str:
    """Flatten a webhook payload (dict / list / str) into a single searchable
    string, so classification + MAC/IP extraction work regardless of the exact
    schema Omada uses."""
    parts = []
    def walk(v):
        if isinstance(v, dict):
            for k, vv in v.items():
                parts.append(str(k))
                walk(vv)
        elif isinstance(v, list):
            for vv in v:
                walk(vv)
        elif v is not None:
            parts.append(str(v))
    walk(payload)
    return " ".join(parts)


@app.route("/api/webhook", methods=["POST"])
@app.route("/api/webhook/<token>", methods=["POST"])
def webhook_receiver(token: str = ""):
    """Receive Omada controller webhook notifications. Accepts any JSON (or
    form/text), stores it verbatim in raw + a classified event in SyslogEvent,
    and always returns 200 so the controller doesn't retry-storm.

    Configure in Omada: Logs → Notifications → enable Webhook, payload template
    'Omada', URL http://THIS-HOST:8082/api/webhook (append /<token> if you set
    WEBHOOK_TOKEN). Enable the specific events you care about."""
    # Parse the body as forgivingly as possible.
    payload = None
    if request.is_json:
        payload = request.get_json(silent=True)
    if payload is None:
        raw_text = request.get_data(as_text=True) or ""
        try:
            payload = json.loads(raw_text) if raw_text.strip() else {}
        except json.JSONDecodeError:
            payload = {"text": raw_text}

    # Auth: if WEBHOOK_TOKEN is set, accept it from any of the three places
    # Omada/clients may carry it — the URL path segment (/api/webhook/<token>),
    # the "access_token" HTTP header (Omada sends this natively), or the
    # "shardSecret" body field. Any match passes.
    if WEBHOOK_TOKEN:
        header_token = (request.headers.get("access_token")
                        or request.headers.get("Access-Token") or "")
        shard = payload.get("shardSecret") if isinstance(payload, dict) else None
        if WEBHOOK_TOKEN not in (token, header_token, shard):
            log.warning("Webhook rejected: bad/missing token from %s", request.remote_addr)
            return jsonify({"ok": False, "error": "unauthorized"}), 401

    raw_json = json.dumps(payload, ensure_ascii=False)[:4000]

    # Omada's real event content lives in a "text" array; "description" is
    # always the boilerplate "This is a webhook message...". Pull the text[]
    # content out first — it's what we classify and summarize on.
    omada_text = ""
    if isinstance(payload, dict):
        t = payload.get("text")
        if isinstance(t, list):
            omada_text = " ".join(str(x) for x in t if x)
        elif isinstance(t, str):
            omada_text = t

    flat = _flatten_webhook(payload)
    # Classify on the meaningful text if present, else the whole flattened body.
    event_type = _classify_webhook(omada_text or flat)
    from datetime import datetime, timezone

    # Best-effort field extraction (schema-tolerant).
    search_text = omada_text or flat
    mac_m = re.search(r"\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b", search_text)
    ip_m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", search_text)
    client_mac = mac_m.group(0).upper().replace(":", "-") if mac_m else None
    # Human-readable summary: prefer the real text[] content, then explicit
    # message-ish fields, then a trimmed flattening. Never the boilerplate
    # "description" alone.
    summary = omada_text or None
    if not summary and isinstance(payload, dict):
        for key in ("msg", "message", "content", "Msg", "operation"):
            if payload.get(key):
                summary = str(payload[key]); break
        # Fall back to description only if nothing better exists.
        if not summary and payload.get("description"):
            summary = str(payload["description"])
    if not summary:
        summary = flat[:300]

    event = {
        "received_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_ip": request.remote_addr,
        "pri": None, "facility": "webhook", "severity": "notice",
        "syslog_ts": None, "hostname": None, "tag": "webhook",
        "message": summary[:2000],
        "category": "Notification",
        "event_type": event_type,
        "client_mac": client_mac,
        "client_ip": ip_m.group(0) if ip_m else None,
        "ssid": None, "channel": None, "device_name": None,
        "raw": raw_json,
    }
    try:
        _store_syslog_event(event)
    except Exception:
        log.exception("Failed to store webhook event")
        # Still 200 — we don't want Omada retrying on our storage hiccup.
    global _webhook_count
    _webhook_count += 1
    log.info("Webhook received from %s → %s", request.remote_addr, event_type)
    return jsonify({"ok": True, "event_type": event_type})


@app.route("/api/syslog/events")
def syslog_events():
    """Query stored syslog events with optional filters. Newest first.

    Query params:
      mac=<MAC>          filter to a device
      event_type=<type>  filter to a classification
      severity=<sev>     filter by severity
      since=<ISO>        only events received after this timestamp
      q=<text>           substring match on the message
      limit=<n>          max rows (default 200, cap 2000)
    """
    q = SyslogEvent.query
    mac = request.args.get("mac")
    if mac:
        q = q.filter(SyslogEvent.client_mac == mac.upper().replace(":", "-"))
    et = request.args.get("event_type")
    if et:
        q = q.filter(SyslogEvent.event_type == et)
    sev = request.args.get("severity")
    if sev:
        q = q.filter(SyslogEvent.severity == sev)
    since = request.args.get("since")
    if since:
        q = q.filter(SyslogEvent.received_at >= since)
    text = request.args.get("q")
    if text:
        q = q.filter(SyslogEvent.message.ilike(f"%{text}%"))
    limit = min(int(request.args.get("limit", 200)), 2000)
    rows = q.order_by(SyslogEvent.id.desc()).limit(limit).all()
    return jsonify({
        "count": len(rows),
        "events": [{
            "id": r.id,
            "received_at": r.received_at,
            "severity": r.severity,
            "facility": r.facility,
            "event_type": r.event_type,
            "category": r.category,
            "client_mac": r.client_mac,
            "client_ip": r.client_ip,
            "ssid": r.ssid,
            "channel": r.channel,
            "hostname": r.hostname,
            "message": r.message,
            "device_name": r.device_name,
            "source_ip": r.source_ip,
            "tag": r.tag,
            "raw": r.raw,
        } for r in rows],
    })


@app.route("/api/syslog/clear", methods=["POST"])
def syslog_clear():
    """Wipe all stored syslog events. Useful when reconfiguring or testing."""
    n = db.session.query(SyslogEvent).delete()
    db.session.commit()
    log.info("Cleared %d syslog events on request", n)
    return jsonify({"cleared": n})


# Allowed analysis/graph windows, in minutes. Keeps queries bounded — the
# flow-log volume means "all events" is never the right scope.
SYSLOG_WINDOWS = {
    "15m": 15, "1h": 60, "6h": 360, "24h": 1440, "7d": 10080,
}


def _window_cutoff(window: str) -> tuple[str, int]:
    """Return (ISO cutoff timestamp, minutes) for a named window. Falls back
    to 1h for anything unrecognized."""
    from datetime import datetime, timezone, timedelta
    minutes = SYSLOG_WINDOWS.get(window, 60)
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    return cutoff, minutes


@app.route("/api/syslog/graphs")
def syslog_graphs():
    """Aggregated data for the Marvis-style charts, constrained to a time
    window (default 1h). Returns:
      - timeline:    event counts bucketed over time (for an activity graph)
      - by_type:     event-type distribution
      - by_severity: severity distribution
      - top_talkers: busiest client devices (resolved to names), excluding
                     pure traffic-flow noise unless it's all there is
      - by_ap:       events per access point (from flow logs' AP MAC)
    All bounded to the window so we never scan the whole table.
    """
    from sqlalchemy import func

    window = request.args.get("window", "1h")
    cutoff, minutes = _window_cutoff(window)
    base = SyslogEvent.query.filter(SyslogEvent.received_at >= cutoff)
    total = base.count()

    # --- Timeline buckets ---
    # Choose a bucket size that yields ~30-60 buckets across the window.
    bucket_sec = max(60, (minutes * 60) // 48)
    timeline_rows = db.session.query(
        SyslogEvent.received_at, SyslogEvent.event_type
    ).filter(SyslogEvent.received_at >= cutoff).all()

    from datetime import datetime, timezone
    buckets: dict = {}
    for received_at, etype in timeline_rows:
        try:
            ts = datetime.strptime(received_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
        epoch = int(ts.timestamp())
        b = epoch - (epoch % bucket_sec)
        if b not in buckets:
            buckets[b] = {"t": b, "total": 0, "flow": 0, "lifecycle": 0}
        buckets[b]["total"] += 1
        if etype == "traffic_flow":
            buckets[b]["flow"] += 1
        else:
            buckets[b]["lifecycle"] += 1
    timeline = sorted(buckets.values(), key=lambda x: x["t"])

    # --- Distributions ---
    # Coerce NULL event_type/severity to a string label — json.dumps sorts dict
    # keys and can't compare str vs None, which would 500 the endpoint.
    by_type = {
        (k or "unknown"): v for k, v in db.session.query(
            SyslogEvent.event_type, func.count(SyslogEvent.id)
        ).filter(SyslogEvent.received_at >= cutoff).group_by(SyslogEvent.event_type).all()
    }

    by_severity = {
        (k or "unknown"): v for k, v in db.session.query(
            SyslogEvent.severity, func.count(SyslogEvent.id)
        ).filter(SyslogEvent.received_at >= cutoff).group_by(SyslogEvent.severity).all()
    }

    # --- Top talkers (busiest clients), with identification ---
    talker_rows = db.session.query(
        SyslogEvent.client_mac, func.count(SyslogEvent.id).label("n")
    ).filter(
        SyslogEvent.received_at >= cutoff, SyslogEvent.client_mac.isnot(None)
    ).group_by(SyslogEvent.client_mac).order_by(func.count(SyslogEvent.id).desc()).limit(12).all()

    def _name_for(mac):
        s = db.session.get(DeviceSetting, mac)
        if s:
            if s.last_synced_name:
                return s.last_synced_name
            if s.ai_analysis:
                try:
                    ai = json.loads(s.ai_analysis)
                    if ai.get("short_name"):
                        return ai["short_name"]
                except (json.JSONDecodeError, TypeError):
                    pass
        # Fall back to AP name — flow logs sometimes carry an AP MAC as the
        # client (mesh / AP management traffic). Label it rather than show bare.
        return resolve_ap(mac)

    top_talkers = [{
        "mac": m, "name": _name_for(m), "events": n,
        "is_ap": bool(resolve_ap(m)),
    } for m, n in talker_rows]

    # --- Events per AP (device_name holds the AP MAC for flow logs) ---
    by_ap_raw = db.session.query(
        SyslogEvent.device_name, func.count(SyslogEvent.id)
    ).filter(
        SyslogEvent.received_at >= cutoff, SyslogEvent.device_name.isnot(None)
    ).group_by(SyslogEvent.device_name).order_by(func.count(SyslogEvent.id).desc()).limit(10).all()
    by_ap = dict(by_ap_raw)
    # Resolved variant: AP MAC → Omada name where known.
    by_ap_named = [{
        "mac": mac, "name": resolve_ap(mac), "events": n
    } for mac, n in by_ap_raw]

    return jsonify({
        "window": window,
        "window_minutes": minutes,
        "bucket_seconds": bucket_sec,
        "total": total,
        "timeline": timeline,
        "by_type": by_type,
        "by_severity": by_severity,
        "top_talkers": top_talkers,
        "by_ap": by_ap,
        "by_ap_named": by_ap_named,
    })


def _summarize_syslog_window(hours: int = 24, max_events: int = 4000) -> dict:
    """Aggregate recent syslog events into a compact, token-efficient summary
    for the AI briefing. Dumping thousands of raw lines would blow the context
    window and bury the signal, so we roll events up into the patterns an
    analyst actually reasons over:
      - counts by event type and severity
      - the noisiest clients (most events) with their identification
      - clients with repeated auth failures (a security/config smell)
      - clients that connect/disconnect repeatedly (flapping)
      - APs going offline
      - a small sample of the most severe raw lines for flavour
    """
    from sqlalchemy import func
    from datetime import datetime, timezone, timedelta

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    base = SyslogEvent.query.filter(SyslogEvent.received_at >= cutoff)
    total = base.count()

    by_type = dict(db.session.query(
        SyslogEvent.event_type, func.count(SyslogEvent.id)
    ).filter(SyslogEvent.received_at >= cutoff).group_by(SyslogEvent.event_type).all())

    by_severity = dict(db.session.query(
        SyslogEvent.severity, func.count(SyslogEvent.id)
    ).filter(SyslogEvent.received_at >= cutoff).group_by(SyslogEvent.severity).all())

    # Noisiest clients (most events).
    noisy = db.session.query(
        SyslogEvent.client_mac, func.count(SyslogEvent.id).label("n")
    ).filter(
        SyslogEvent.received_at >= cutoff, SyslogEvent.client_mac.isnot(None)
    ).group_by(SyslogEvent.client_mac).order_by(func.count(SyslogEvent.id).desc()).limit(15).all()

    # Repeated auth failures per client.
    auth_fails = db.session.query(
        SyslogEvent.client_mac, func.count(SyslogEvent.id).label("n")
    ).filter(
        SyslogEvent.received_at >= cutoff,
        SyslogEvent.event_type == "auth_failed",
        SyslogEvent.client_mac.isnot(None),
    ).group_by(SyslogEvent.client_mac).order_by(func.count(SyslogEvent.id).desc()).limit(10).all()

    # Flapping: clients with many connect+disconnect events.
    flap = db.session.query(
        SyslogEvent.client_mac, func.count(SyslogEvent.id).label("n")
    ).filter(
        SyslogEvent.received_at >= cutoff,
        SyslogEvent.event_type.in_(["client_connect", "client_disconnect", "reconnect"]),
        SyslogEvent.client_mac.isnot(None),
    ).group_by(SyslogEvent.client_mac).order_by(func.count(SyslogEvent.id).desc()).limit(10).all()

    # AP / infra offline events (no client MAC, infra event types).
    infra = base.filter(
        SyslogEvent.event_type.in_(["offline", "online"])
    ).order_by(SyslogEvent.id.desc()).limit(20).all()

    # A few of the most severe raw lines (error/warning) for texture.
    severe = base.filter(
        SyslogEvent.severity.in_(["error", "err", "warning", "warn", "critical", "alert"])
    ).order_by(SyslogEvent.id.desc()).limit(25).all()

    # Resolve client MACs to identification info so the briefing can name them.
    def _client_label(mac):
        if not mac:
            return "?"
        # Access point? Label it explicitly so the briefing doesn't mistake
        # infrastructure for a rogue/chatty client device.
        ap_name = resolve_ap(mac)
        if ap_name:
            return f"{mac} / {ap_name} [ACCESS POINT — infrastructure, relays client traffic]"
        s = db.session.get(DeviceSetting, mac)
        bits = [mac]
        if s:
            if s.last_synced_name:
                bits.append(s.last_synced_name)
            if s.ai_analysis:
                try:
                    ai = json.loads(s.ai_analysis)
                    if ai.get("short_name"):
                        bits.append(ai["short_name"])
                    elif ai.get("brief_description"):
                        bits.append(ai["brief_description"])
                except (json.JSONDecodeError, TypeError):
                    pass
            if s.notes:
                bits.append(f"notes: {s.notes[:80]}")
        # Dedupe consecutive/identical fragments (e.g. synced name == AI short_name)
        seen = set()
        deduped = []
        for b in bits:
            key = b.lower().strip()
            if key not in seen:
                seen.add(key)
                deduped.append(b)
        return " / ".join(deduped)

    return {
        "window_hours": hours,
        "total_events": total,
        "by_type": by_type,
        "by_severity": by_severity,
        "noisy_clients": [{"client": _client_label(m), "events": n} for m, n in noisy],
        "auth_failures": [{"client": _client_label(m), "fails": n} for m, n in auth_fails],
        "flapping_clients": [{"client": _client_label(m), "transitions": n} for m, n in flap],
        "infra_events": [{"type": e.event_type, "message": (e.message or "")[:160],
                          "at": e.received_at} for e in infra],
        "severe_samples": [{"sev": e.severity, "type": e.event_type,
                            "client": e.client_mac, "message": (e.message or "")[:200]}
                           for e in severe],
    }


@app.route("/api/syslog/analyze", methods=["POST"])
def syslog_analyze():
    """Marvis-style network-health briefing. Aggregates the recent syslog
    window + client identification and asks Gemini to surface the top issues,
    likely root causes, and recommended actions — a 'morning cup of coffee'
    view of what needs attention."""
    if not GEMINI_API_KEY:
        return jsonify({"error": "No Gemini API key configured — set one in Settings"}), 400

    # Accept either a named window (15m/1h/6h/24h/7d) — shared with the graphs
    # selector — or an explicit hours value. Named window takes precedence.
    body = (request.json or {}) if request.is_json else {}
    window = body.get("window")
    if window and window in SYSLOG_WINDOWS:
        minutes = SYSLOG_WINDOWS[window]
        hours = max(1, round(minutes / 60))
        window_label = window
    else:
        hours = int(body.get("hours", 24))
        window_label = f"last {hours}h"
    summary = _summarize_syslog_window(hours=hours)

    if summary["total_events"] == 0:
        return jsonify({
            "briefing": f"No syslog events in {window_label}. Either the "
                        f"network has been quiet, or Omada syslog export isn't "
                        f"reaching this host yet (point it at UDP/{SYSLOG_PORT}).",
            "events_analyzed": 0,
            "window": window_label,
            "model": get_active_gemini_model(),
        })

    system_prompt = (
        "You are a senior network operations analyst producing a concise "
        "morning briefing for a home/small-office network managed by TP-Link "
        "Omada. You are given an AGGREGATED summary of the last "
        f"{hours} hours of syslog events (already rolled up — you don't see "
        "every raw line). Your job, in the style of an AIOps assistant:\n"
        "\n"
        "1. Lead with a one-line overall health verdict (healthy / minor "
        "issues / needs attention).\n"
        "2. List the TOP 3-5 issues worth the operator's attention, most "
        "important first. For each: what's happening, which device(s) "
        "(name them by their identification, and include the MAC so the UI "
        "can link to them), a likely root cause, and a concrete recommended "
        "action.\n"
        "3. Call out anything that looks like a security concern (repeated "
        "auth failures could be a wrong saved password OR a brute-force "
        "attempt — say which is more likely given the pattern).\n"
        "4. Note what looks normal/healthy so the operator isn't alarmed by "
        "routine churn (a phone connecting/disconnecting as someone comes and "
        "goes is normal; a stationary IoT device flapping 50x/hour is not).\n"
        "\n"
        "Be specific and grounded in the data provided — don't invent events. "
        "If the data is benign, say so plainly rather than manufacturing "
        "concerns. Use plain text with short paragraphs or simple bullet "
        "lists. Always include device MACs when discussing specific devices."
    )

    user_content = (
        "Here is the aggregated network event summary to analyze:\n\n"
        + json.dumps(summary, indent=2)
    )

    model_id = get_active_gemini_model()
    payload = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": user_content}]}],
        "generationConfig": {"temperature": 0.4, "maxOutputTokens": 2048},
    }
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{model_id}:generateContent")
    try:
        r = requests.post(url, params={"key": GEMINI_API_KEY},
                          json=payload, timeout=90)
        r.raise_for_status()
        body = r.json()
        briefing = body["candidates"][0]["content"]["parts"][0]["text"]
    except requests.HTTPError as exc:
        detail = exc.response.text if exc.response is not None else str(exc)
        log.error("syslog_analyze: Gemini HTTP error: %s", detail)
        return jsonify({"error": f"Gemini API error: {detail[:300]}"}), 502
    except (KeyError, IndexError) as exc:
        return jsonify({"error": f"Unexpected Gemini response: {exc}"}), 502
    except Exception as exc:
        log.exception("syslog_analyze: Gemini call failed")
        return jsonify({"error": str(exc)}), 502

    log.info("Network briefing generated over %d events (%dh window)",
             summary["total_events"], hours)
    return jsonify({
        "briefing": briefing,
        "events_analyzed": summary["total_events"],
        "window": window_label,
        "model": model_id,
    })


@app.route("/api/dhcp_manual", methods=["POST"])
def dhcp_manual():
    """Manually set a DHCP fingerprint and/or vendor class for a MAC.
    Useful when scapy isn't viable (no raw sockets, isolated VLAN, etc.)
    or for one-off testing."""
    data = request.json or {}
    mac = data.get("mac")
    if not mac:
        return jsonify({"error": "mac required"}), 400
    fp = (data.get("dhcp_fingerprint") or "").strip()
    vc = (data.get("dhcp_vendor_class") or "").strip()
    # Allow clearing by passing empty strings.
    setting = get_setting(mac)
    if not setting:
        setting = DeviceSetting(mac=mac, auto_sync=False, first_seen=iso_now())
        db.session.add(setting)
    setting.dhcp_fingerprint = fp or None
    setting.dhcp_vendor_class = vc or None
    setting.dhcp_captured_at = iso_now() if (fp or vc) else None
    db.session.commit()
    return jsonify({
        "status": "success",
        "mac": mac,
        "dhcp_fingerprint": setting.dhcp_fingerprint,
        "dhcp_vendor_class": setting.dhcp_vendor_class,
    })


@app.route("/api/toggle_auto", methods=["POST"])
def toggle_auto():
    data = request.json or {}
    mac = data.get("mac")
    state = bool(data.get("state"))
    if not mac:
        return jsonify({"error": "mac required"}), 400
    setting = get_setting(mac)
    if not setting:
        setting = DeviceSetting(mac=mac, auto_sync=state)
        db.session.add(setting)
    else:
        setting.auto_sync = state
    db.session.commit()
    return jsonify({"status": "success", "auto_sync": state})


@app.route("/api/sync_name", methods=["POST"])
def sync_name():
    data = request.json or {}
    mac = data.get("mac")
    name = data.get("name")
    if not mac or not name:
        return jsonify({"error": "mac and name required"}), 400
    try:
        result = omada.rename_client(mac, name)
    except Exception as exc:
        log.exception("rename failed")
        return jsonify({"errorCode": -1, "error": str(exc)}), 502
    # Persist what we last pushed so the UI can show "in sync".
    setting = get_setting(mac) or DeviceSetting(mac=mac, auto_sync=False)
    setting.last_synced_name = name[:128]
    db.session.add(setting)
    db.session.commit()
    return jsonify(result)


@app.route("/api/sync_all_mismatched", methods=["POST"])
@app.route("/api/sync_all_auto", methods=["POST"])  # legacy alias
def sync_all_mismatched():
    """Batch sync every device whose current name differs from its proposed name.

    Optional body params:
      auto_only: bool — if True, only sync devices where DeviceSetting.auto_sync
                        is also True. Default False (matches the button label).
      dry_run:   bool — if True, return what *would* be synced without doing it.

    Returns:
      { "synced": N, "skipped": N, "errors": [...], "candidates": [...] (dry-run) }
    """
    data = request.json or {}
    auto_only = bool(data.get("auto_only", False))
    dry_run = bool(data.get("dry_run", False))

    try:
        raw_clients = omada.list_clients()
    except Exception as exc:
        return jsonify({"error": str(exc), "synced": 0}), 502

    tpl_row = GlobalSetting.query.first()
    template = tpl_row.naming_template if tpl_row else DEFAULT_TEMPLATE

    candidates: list[dict] = []
    for c in raw_clients:
        mac = c.get("mac")
        if not mac:
            continue
        setting = get_setting(mac)
        if auto_only and not (setting and setting.auto_sync):
            continue

        fb_cache: dict = {}
        ai_cache: dict = {}
        notes: str | None = None
        if setting:
            if setting.fingerbank_cache:
                try:
                    fb_cache = json.loads(setting.fingerbank_cache)
                except json.JSONDecodeError:
                    pass
            if setting.ai_analysis:
                try:
                    ai_cache = json.loads(setting.ai_analysis)
                except json.JSONDecodeError:
                    pass
            notes = setting.notes

        ctx = build_template_ctx(c, fb_cache, ai_cache, notes)
        proposed = render_template_name(template, ctx, fb_cache)[:128]
        current = c.get("name") or ""
        if current == proposed:
            continue
        candidates.append({
            "mac": mac,
            "current": current,
            "proposed": proposed,
        })

    if dry_run:
        return jsonify({
            "dry_run": True,
            "would_sync": len(candidates),
            "candidates": candidates,
        })

    synced = 0
    errors: list[dict] = []
    for cand in candidates:
        mac = cand["mac"]
        proposed = cand["proposed"]
        try:
            omada.rename_client(mac, proposed)
            setting = get_setting(mac) or DeviceSetting(mac=mac, auto_sync=False)
            setting.last_synced_name = proposed
            db.session.add(setting)
            synced += 1
        except Exception as exc:
            log.exception("rename failed for %s", mac)
            errors.append({"mac": mac, "error": str(exc)[:200]})
    db.session.commit()

    return jsonify({
        "synced": synced,
        "errors": errors,
        "total_candidates": len(candidates),
    })


# Remove the old function below — it's replaced by sync_all_mismatched.
def _deprecated_sync_all_auto():
    pass


# ---------------------------------------------------------------------------
# Chatbot (/api/chat)
# ---------------------------------------------------------------------------
# Lets the user ask questions about the device fleet in natural language.
# Two scopes:
#   - "all"        — system prompt embeds a compact roster of every device
#                     plus aggregate counts. Good for "how many cameras", etc.
#   - "<mac>"      — system prompt embeds full data for that one device.
#                     Good for "why does AI think this is a Roku", etc.
# Multi-turn: the client sends the full message history each turn, we forward
# it to Gemini as alternating user/model parts. No streaming for v1 — the
# dataset is small enough that responses arrive in 2-5s.

def _enrich_clients_for_display(raw_clients: list) -> list:
    """Hydrate Omada client records with the same resolved fields the UI sees
    via /api/clients: notes, AI cache, Fingerbank cache, mDNS observations,
    DHCP fingerprint/vendor class, first/last seen, resolved name/os/type,
    dhcp_hostname, oui_vendor, proposed_name, identified flag.

    Pure: doesn't touch first_seen/last_seen counters or kick async lookups.
    Used by /api/chat to give Gemini the same view of each device the user
    sees in the table."""
    tpl_row = GlobalSetting.query.first()
    template = tpl_row.naming_template if tpl_row else DEFAULT_TEMPLATE
    out = []
    for c in raw_clients:
        mac = c.get("mac", "")
        setting = db.session.get(DeviceSetting, mac)
        fb_cache: dict = {}
        ai_cache: dict = {}
        mdns_data: dict = {}
        if setting:
            if setting.fingerbank_cache:
                try: fb_cache = json.loads(setting.fingerbank_cache)
                except json.JSONDecodeError: pass
            if setting.ai_analysis:
                try: ai_cache = json.loads(setting.ai_analysis)
                except json.JSONDecodeError: pass
            if setting.mdns_data:
                try: mdns_data = json.loads(setting.mdns_data)
                except json.JSONDecodeError: pass
        notes = (setting.notes or "") if setting else ""
        ctx = build_template_ctx(c, fb_cache, ai_cache, notes)
        proposed = render_template_name(template, ctx, fb_cache)[:128]

        c["proposed_name"] = proposed
        c["host_name_resolved"] = ctx["host"]
        c["dhcp_hostname"] = c.get("hostName") or ""
        c["oui_vendor"] = ctx["vdr"]
        c["resolved_name"] = ctx["name"]
        c["resolved_os"]   = ctx["os"]
        c["resolved_type"] = ctx["type"]
        c["fb_data"] = fb_cache
        c["ai_data"] = ai_cache
        c["notes"] = notes
        c["identified"] = bool(notes) or bool(ai_cache)
        if setting:
            c["dhcp_fingerprint"]  = setting.dhcp_fingerprint
            c["dhcp_vendor_class"] = setting.dhcp_vendor_class
            c["last_synced_name"]  = setting.last_synced_name
            c["first_seen"]        = setting.first_seen
            c["last_seen"]         = setting.last_seen
            if mdns_data:
                c["mdns_data"] = mdns_data
        out.append(c)
    return out


def _build_fleet_summary(clients: list) -> str:
    """Compact roster + per-device signal mini-dossier. For each device we
    include the raw signals an analyst needs (DHCP fingerprint, vendor class,
    mDNS services, OUI prefix), with priority on unidentified ones — those
    are what the user will most often ask Gemini to investigate."""
    if not clients:
        return "No clients currently known."
    lines = [f"Total devices: {len(clients)}"]
    by_type: dict[str, int] = {}
    by_os: dict[str, int] = {}
    identified = 0
    for c in clients:
        t = c.get("resolved_type") or "Unknown"
        o = c.get("resolved_os") or "Unknown"
        by_type[t] = by_type.get(t, 0) + 1
        by_os[o] = by_os.get(o, 0) + 1
        if c.get("identified"):
            identified += 1
    lines.append(f"Identified: {identified}  Unknown: {len(clients) - identified}")
    lines.append("By type: " + ", ".join(f"{k}={v}" for k, v in sorted(by_type.items(), key=lambda kv: -kv[1])))
    lines.append("By OS:   " + ", ".join(f"{k}={v}" for k, v in sorted(by_os.items(), key=lambda kv: -kv[1])))
    lines.append("")
    lines.append("=== Per-device dossier ===")
    # Sort unknowns first so analyst-mode questions get the most useful
    # context near the top of the prompt window.
    sorted_clients = sorted(clients, key=lambda c: (bool(c.get("identified")), c.get("mac") or ""))
    for c in sorted_clients:
        mac = c.get("mac") or "?"
        oui = mac[:8] if len(mac) >= 8 else "?"
        # Detect locally-administered MAC (2nd bit of first octet set).
        # 0x02/0x06/0x0A/0x0E and similar high-nibble patterns mean VM/container/random.
        local_admin = ""
        try:
            first_byte = int(mac.split("-")[0] if "-" in mac else mac.split(":")[0], 16)
            if first_byte & 0x02:
                local_admin = " [LOCALLY-ADMINISTERED MAC — likely VM/container/random]"
        except (ValueError, IndexError):
            pass

        flag = "✓ identified" if c.get("identified") else "✗ UNIDENTIFIED"
        lines.append("")
        lines.append(f"--- {mac} [{flag}] ---")
        lines.append(
            f"  name={c.get('name') or '(none)'}  "
            f"hostname={c.get('dhcp_hostname') or '(none)'}  "
            f"ip={c.get('ip') or '?'}"
        )
        lines.append(
            f"  oui={oui}{local_admin}  "
            f"vendor={c.get('oui_vendor') or c.get('vendor') or '(unknown)'}"
        )
        lines.append(
            f"  omada_os={c.get('osName') or c.get('os') or '(none)'}  "
            f"omada_type={c.get('deviceType') or '(none)'}  "
            f"omada_cat={c.get('deviceCategory') or '(none)'}"
        )
        if c.get("wireless"):
            lines.append(f"  ssid={c.get('ssid') or '(none)'}  ap={c.get('apName') or '(none)'}  (wireless)")
        else:
            lines.append(f"  switch={c.get('switchName') or '(none)'}  (wired)")
        if c.get("dhcp_fingerprint"):
            lines.append(f"  dhcp_option_55={c['dhcp_fingerprint']}")
        if c.get("dhcp_vendor_class"):
            lines.append(f"  dhcp_option_60={c['dhcp_vendor_class']}")
        mdns = c.get("mdns_data") or {}
        if mdns.get("services"):
            lines.append(f"  mdns_services={', '.join(mdns['services'])}")
        if mdns.get("txt"):
            txts = ", ".join(f"{k}={v}" for k, v in list(mdns["txt"].items())[:8])
            lines.append(f"  mdns_txt={txts}")
        if mdns.get("instance_names"):
            lines.append(f"  mdns_instance={', '.join(mdns['instance_names'][:3])}")
        ai = c.get("ai_data") or {}
        if ai.get("suggested_label"):
            lines.append(f"  prior_ai_guess={ai.get('suggested_label')} (conf={ai.get('confidence', '?')})")
        if c.get("notes"):
            notes = c["notes"].replace("\n", " ").strip()[:200]
            lines.append(f"  owner_notes={notes}")

    # Network-wide syslog summary (last 24h) so fleet-scope chat can answer
    # event questions like "any auth failures today?" without a separate call.
    try:
        from sqlalchemy import func
        from datetime import datetime, timezone, timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
        recent_total = SyslogEvent.query.filter(SyslogEvent.received_at >= cutoff).count()
        if recent_total:
            by_type = dict(db.session.query(
                SyslogEvent.event_type, func.count(SyslogEvent.id)
            ).filter(SyslogEvent.received_at >= cutoff)
             .group_by(SyslogEvent.event_type).all())
            lines.append("")
            lines.append(f"=== Syslog (last 24h): {recent_total} events ===")
            lines.append("By type: " + ", ".join(f"{k}={v}" for k, v in
                         sorted(by_type.items(), key=lambda kv: -kv[1])))
    except Exception:
        pass  # syslog is best-effort context; never break chat over it
    return "\n".join(lines)


def _build_device_dossier(c: dict) -> str:
    """Full dossier for a single device, for per-MAC scope. Includes
    everything we'd send to analyze_with_gemini, plus AI cache and notes
    and mDNS observations."""
    lines = [
        f"=== Device dossier: {c.get('mac', '?')} ===",
        f"Current Omada name: {c.get('name') or '(none)'}",
        f"DHCP hostname:      {c.get('dhcp_hostname') or '(none)'}",
        f"IP address:         {c.get('ip', '?')}",
        f"Connection:         {'wireless' if c.get('wireless') else 'wired'}",
        f"SSID:               {c.get('ssid', '(n/a)')}",
        f"AP / switch:        {c.get('apName') or c.get('switchName') or '(n/a)'}",
        f"Omada OS guess:     {c.get('osName') or c.get('os') or '(none)'}",
        f"Omada type guess:   {c.get('deviceType') or '(none)'}",
        f"Omada vendor:       {c.get('vendor') or c.get('manufacturer') or '(none)'}",
        f"OUI vendor:         {c.get('oui_vendor') or '(none)'}",
        f"Resolved name:      {c.get('resolved_name') or '(none)'}",
        f"Resolved OS:        {c.get('resolved_os') or '(none)'}",
        f"Resolved type:      {c.get('resolved_type') or '(none)'}",
        f"Proposed name:      {c.get('proposed_name') or '(none)'}",
        f"Last synced name:   {c.get('last_synced_name') or '(never)'}",
        f"First seen:         {c.get('first_seen') or '(unknown)'}",
        f"Last seen:          {c.get('last_seen') or '(unknown)'}",
    ]
    if c.get("dhcp_fingerprint"):
        lines.append(f"DHCP option 55:     {c['dhcp_fingerprint']}")
    if c.get("dhcp_vendor_class"):
        lines.append(f"DHCP option 60:     {c['dhcp_vendor_class']}")
    if c.get("mdns_data"):
        m = c["mdns_data"]
        if m.get("services"):
            lines.append(f"mDNS services:      {', '.join(m['services'])}")
        if m.get("txt"):
            txts = ", ".join(f"{k}={v}" for k, v in m["txt"].items())
            lines.append(f"mDNS TXT records:   {txts}")
        if m.get("instance_names"):
            lines.append(f"mDNS instances:     {', '.join(m['instance_names'])}")
    if c.get("notes"):
        lines.append(f"\nOwner notes: {c['notes']}")
    if c.get("ai_data"):
        ai = c["ai_data"]
        lines.append("\nGemini analysis (cached):")
        for k in ("short_name", "normalized_os", "normalized_type",
                  "manufacturer", "product_type", "confidence",
                  "reasoning", "security_notes"):
            if ai.get(k):
                lines.append(f"  {k}: {ai[k]}")
    if c.get("fb_data"):
        fb = c["fb_data"]
        dev = (fb.get("device") or {}).get("name")
        if dev:
            lines.append(f"\nFingerbank device: {dev}")
            parents = fb.get("device", {}).get("parents") or []
            if parents:
                chain = " > ".join(p.get("name", "?") for p in parents)
                lines.append(f"Fingerbank hierarchy: {chain}")

    # Recent syslog events for this device — lets the chat answer questions
    # like "why did this keep dropping last night?" with actual event history.
    mac = c.get("mac")
    if mac:
        recent = (SyslogEvent.query
                  .filter(SyslogEvent.client_mac == mac)
                  .order_by(SyslogEvent.id.desc()).limit(40).all())
        if recent:
            lines.append(f"\nRecent syslog events ({len(recent)}, newest first):")
            for e in recent:
                ts = e.received_at or "?"
                lines.append(f"  [{ts}] {e.severity or '-'}/{e.event_type or '-'}: "
                             f"{(e.message or '')[:140]}")
    return "\n".join(lines)


def _build_chat_system_prompt(scope: str, clients: list) -> str:
    """Compose the system instruction for Gemini based on scope.

    Positions Gemini as a senior network/security engineer doing forensic
    device analysis, not a passive Q&A tool. Encourages educated reasoning
    from raw signals (DHCP option 55 fingerprints, mDNS service patterns,
    OUI prefixes, TXT records, vendor class strings) — the kind of work a
    PacketFence / NetAlertX / NAC analyst does daily."""
    header = (
        "You are a senior network and security engineer assisting the "
        "administrator of a home/lab network managed by TP-Link Omada. "
        "Think and answer like a forensic device analyst: you take raw "
        "signals — DHCP option 55 parameter request lists, option 60 "
        "vendor class strings, mDNS/Bonjour service types, mDNS TXT "
        "records, MAC OUI prefixes, hostname patterns — and reason from "
        "first principles to identify what a device is, who made it, "
        "what OS it runs, and what it's used for.\n"
        "\n"
        "Key analyst knowledge to apply (you already know this; use it):\n"
        "  • OUI prefixes map vendors: 00:50:56=VMware, 52:54:00=QEMU/KVM, "
        "08:00:27=VirtualBox, B8:27:EB/DC:A6:32/E4:5F:01=Raspberry Pi, "
        "8C:F1:12/8C:85:90/D8:1F:99=Apple, F4:F5:E8=Google Nest, "
        "00:1A:11=Google, AC:84:C6=TP-Link, 24:62:AB=Espressif, etc. "
        "Locally-administered MACs (02:*, 06:*, 0A:*, 0E:* — i.e. the 2nd "
        "bit of the first octet is set) almost always mean a virtual "
        "interface: VM, container, randomized client privacy MAC, etc.\n"
        "  • DHCP option 55 fingerprints have well-known patterns: "
        "'1,3,6,15,28,42,121' is older Android, '1,121,3,6,15,119,252' is "
        "current iOS/macOS, '1,3,6,15,31,33,43,44,46,47,119,121,249,252' "
        "is modern Windows, etc. Espressif ESP32 IoT typically requests "
        "'1,3,28,6'.\n"
        "  • Option 60 vendor class often reveals device family verbatim: "
        "'AppleTV5,3', 'android-dhcp-13', 'dhcpcd-9.4.1:Linux:armv8l', "
        "'MSFT 5.0', 'udhcp 1.x.x', etc.\n"
        "  • mDNS services classify devices instantly: _airplay/_raop = "
        "AirPlay receiver, _googlecast = Chromecast/Nest Audio, _hap = "
        "HomeKit accessory, _hue = Philips Hue bridge, _spotify-connect = "
        "Sonos/Spotify-aware speaker, _ipp/_printer = network printer, "
        "_companion-link = Apple device, _miio = Xiaomi IoT, _shelly = "
        "Shelly relay, _meshcop = Thread border router, etc.\n"
        "  • TXT records often contain model strings verbatim: md= or "
        "model= keys, ty= friendly-name, vers= firmware version.\n"
        "\n"
        "When the user asks about an unknown or unidentified device, "
        "DON'T just say 'unknown — not enough info'. Instead, walk through "
        "the available evidence (OUI → likely vendor; DHCP fingerprint → "
        "likely OS family; mDNS services → likely role; hostname pattern "
        "→ likely product line) and offer your best guess with explicit "
        "confidence (high/medium/low) and reasoning. If multiple "
        "interpretations are plausible, list the top two. If genuinely "
        "nothing is known, say what additional capture would resolve it "
        "(e.g. 'next DHCP renewal will give us option 55, that should "
        "narrow OS to within a vendor family').\n"
        "\n"
        "Format: plain text by default, but feel free to use short "
        "bulleted breakdowns for per-device analysis when comparing "
        "several devices. Always include the device's MAC address when "
        "discussing it so the user can click through (the UI makes MACs "
        "tappable). Be direct, like a colleague debugging next to them; "
        "skip filler.\n"
        "\n"
        "=== Live query tools ===\n"
        "You have tools to read the network's REAL syslog/event data. NEVER "
        "guess at counts, event histories, or which devices have problems — "
        "call a tool and answer from the result. Tools available:\n"
        "  • find_device — resolve a plain-language device reference ('my "
        "iPad', a partial name, an IP) to a MAC. Call this FIRST whenever the "
        "user names a specific device, then use the MAC in other tools.\n"
        "  • count_events — count events (optionally by device/type/window). "
        "For 'how many times did X disconnect'.\n"
        "  • list_events — recent events matching filters. For 'show me what "
        "happened with X'.\n"
        "  • status_of_clients — rank devices by problem events. For 'which "
        "devices are having trouble'.\n"
        "  • troubleshoot_device — full diagnostic for one device. For 'why "
        "can't X connect', 'what's wrong with X'.\n"
        "  • roaming_of — a device's roaming history. For 'is X roaming too "
        "much'.\n"
        "  • aggregate_events — group + rank events in ONE call (top talkers, "
        "busiest APs, type breakdown, trend over time) with counts, "
        "percentages and per-hour rates. ALWAYS prefer this over making many "
        "count_events calls. When the answer is a ranking, distribution, or "
        "trend that a picture would clarify, set chart=true so the UI draws "
        "it — then summarize the key takeaway in text above it. Don't chart a "
        "single number.\n"
        "After calling tools, synthesize the results into a clear, grounded "
        "answer. If a tool returns zero events, say so plainly rather than "
        "speculating. Cite the actual numbers you got back. The system handles "
        "all arithmetic (percentages, rates) for you in the tool results — use "
        "those values rather than computing your own.\n"
        "\n"
        "IMPORTANT — APs vs clients: in this network's flow logs, the busiest "
        "MACs are usually ACCESS POINTS (the AP that relayed a client's "
        "traffic), not rogue or chatty client devices. Tool results mark these "
        "with is_ap=true and resolve them to AP names when known. Never "
        "describe an access point as an 'unidentified device', 'media "
        "streamer', or 'device phoning home' — it's infrastructure carrying "
        "everyone's traffic. When a top talker is an AP, say so.\n"
        "\n"
    )
    if scope == "all":
        return header + "=== Current network state ===\n" + _build_fleet_summary(clients)
    # Per-device scope: scope is a MAC; find it in the list.
    target = next((c for c in clients if c.get("mac") == scope), None)
    if target is None:
        return (header + f"(The user asked about MAC {scope} but that "
                f"device is not in the current Omada client list — it may "
                f"be offline. Acknowledge this and offer to discuss it "
                f"based on whatever historical data the user provides.)")
    return header + _build_device_dossier(target)


# ---------------------------------------------------------------------------
# Marvis-style query tools for the chatbot
# ---------------------------------------------------------------------------
# Gemini drives the conversation in natural language but, instead of guessing,
# it calls these structured tools to read real data — the modern equivalent of
# Marvis's LIST / COUNT / STATUSOF / TROUBLESHOOT / ROAMINGOF query language.
# Each tool returns plain dicts/lists that get fed back to the model.

# Gemini function-calling schema (subset of OpenAPI). Declared once, sent with
# every chat request.
CHAT_TOOLS = [{
    "functionDeclarations": [
        {
            "name": "find_device",
            "description": "Resolve a device the user names in plain language "
                           "(e.g. 'my iPad', 'the front gate camera', a partial "
                           "name, IP, or MAC) to its MAC address and identity. "
                           "Call this first when the user refers to a specific "
                           "device so later tool calls can use its MAC.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string",
                              "description": "Name, partial name, IP, hostname, "
                                             "or MAC the user mentioned."},
                },
                "required": ["query"],
            },
        },
        {
            "name": "count_events",
            "description": "Count syslog events matching filters over a time "
                           "window. Use for 'how many times…', 'how many auth "
                           "failures…' questions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "mac": {"type": "string", "description": "Client MAC (dash or colon form). Omit for all devices."},
                    "event_type": {"type": "string", "description": "One of: client_connect, client_disconnect, reconnect, roamed, roaming, auth_failed, deauth, dhcp, online, offline, traffic_flow, other."},
                    "hours": {"type": "number", "description": "Look-back window in hours (default 24)."},
                },
            },
        },
        {
            "name": "list_events",
            "description": "List recent syslog events matching filters, newest "
                           "first. Use for 'show me…', 'what happened with…'. "
                           "Returns up to 'limit' events.",
            "parameters": {
                "type": "object",
                "properties": {
                    "mac": {"type": "string"},
                    "event_type": {"type": "string"},
                    "hours": {"type": "number", "description": "Look-back window in hours (default 24)."},
                    "limit": {"type": "number", "description": "Max events to return (default 20, cap 50)."},
                },
            },
        },
        {
            "name": "status_of_clients",
            "description": "Rank clients by how many problem events (auth "
                           "failures, disconnects, deauths) they've had over the "
                           "window — the worst first. Use for 'which devices are "
                           "having trouble', 'any connectivity issues'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "hours": {"type": "number", "description": "Look-back window in hours (default 24)."},
                },
            },
        },
        {
            "name": "troubleshoot_device",
            "description": "Gather a full diagnostic picture for one device: its "
                           "identity, recent event breakdown by type, and a "
                           "sample of its most recent events. Use for 'why can't "
                           "X connect', 'troubleshoot X', 'what's wrong with X'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "mac": {"type": "string", "description": "The device's MAC (resolve with find_device first if needed)."},
                    "hours": {"type": "number", "description": "Look-back window in hours (default 24)."},
                },
                "required": ["mac"],
            },
        },
        {
            "name": "roaming_of",
            "description": "Show a device's roaming history over a period — which "
                           "APs it moved between and when, as an ordered hop "
                           "sequence with a per-AP dwell summary. Use for 'show "
                           "roaming for X', 'how much has X roamed this week', 'is "
                           "X flapping between APs'. Set chart=true to visualize "
                           "the roam timeline.",
            "parameters": {
                "type": "object",
                "properties": {
                    "mac": {"type": "string"},
                    "hours": {"type": "number", "description": "Look-back window in hours (default 24; use 168 for 'last 7 days')."},
                    "chart": {"type": "boolean", "description": "If true, include a timeline chart of roam events."},
                },
                "required": ["mac"],
            },
        },
        {
            "name": "aggregate_events",
            "description": "Aggregate events in ONE call — far better than many "
                           "count_events calls. Groups events and returns ranked "
                           "buckets with counts, percentages, and a per-hour rate. "
                           "Use for 'top talkers', 'busiest APs', 'breakdown by "
                           "type', 'which devices are noisiest'. "
                           "group_by: 'client' (busiest devices, name-resolved), "
                           "'ap' (busiest access points), 'event_type' "
                           "(distribution), or 'time' (counts per time bucket for "
                           "a trend). Set chart=true when a visual would help the "
                           "user (ranked lists, distributions, trends) — the UI "
                           "renders it as a chart. Pick chart_type: 'bar' for "
                           "rankings/distributions, 'line' for time trends, "
                           "'doughnut' for proportions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "group_by": {"type": "string", "description": "client | ap | event_type | time"},
                    "event_type": {"type": "string", "description": "Optional: restrict to one event type before aggregating."},
                    "mac": {"type": "string", "description": "Optional: restrict to one device (useful with group_by=time or event_type)."},
                    "hours": {"type": "number", "description": "Look-back window in hours (default 1)."},
                    "limit": {"type": "number", "description": "Top-N buckets to return for client/ap/event_type (default 8, cap 20)."},
                    "chart": {"type": "boolean", "description": "If true, include a chart spec the UI will render."},
                    "chart_type": {"type": "string", "description": "bar | line | doughnut. Defaults: bar for rankings, line for time."},
                },
                "required": ["group_by"],
            },
        },
    ]
}]


def _hours_cutoff(hours: float) -> str:
    from datetime import datetime, timezone, timedelta
    return (datetime.now(timezone.utc) - timedelta(hours=hours or 24)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def _device_identity(mac: str) -> dict:
    """Compact identity dict for a MAC: synced/AI name, type, vendor, plus an
    is_ap flag and AP name when the MAC is one of our access points. Used by the
    chat tools so answers can name devices and link back to them."""
    out = {"mac": mac, "name": None, "type": None, "vendor": None,
           "notes": None, "is_ap": False}
    s = db.session.get(DeviceSetting, mac)
    if s:
        out["notes"] = (s.notes or None)
        if s.last_synced_name:
            out["name"] = s.last_synced_name
        if s.ai_analysis:
            try:
                ai = json.loads(s.ai_analysis)
                out["name"] = out["name"] or ai.get("short_name") or ai.get("brief_description")
                out["type"] = ai.get("device_type") or ai.get("type")
                out["vendor"] = ai.get("vendor") or ai.get("manufacturer")
            except (json.JSONDecodeError, TypeError):
                pass
        out["vendor"] = out["vendor"] or getattr(s, "oui_vendor", None)
    # AP fallback: if this MAC is one of our access points, label it as such.
    ap_name = resolve_ap(mac)
    if ap_name:
        out["is_ap"] = True
        out["name"] = out["name"] or ap_name
        out["type"] = out["type"] or "Access Point"
    return out


def _tool_find_device(args: dict, clients: list) -> dict:
    """Resolve a free-text reference to a device. Searches the live client list,
    DeviceSettings, and access points by name, IP, hostname, and MAC."""
    q = (args.get("query") or "").strip().lower()
    if not q:
        return {"error": "empty query"}
    q_mac = q.upper().replace(":", "-")
    matches = []
    for c in clients:
        mac = c.get("mac", "")
        hay = " ".join(str(x) for x in [
            c.get("name"), c.get("dhcp_hostname"), c.get("resolved_name"),
            c.get("ip"), mac, c.get("oui_vendor"), c.get("resolved_type"),
        ] if x).lower()
        if q in hay or q_mac in mac.upper():
            matches.append({
                "mac": mac,
                "name": c.get("name") or c.get("resolved_name") or c.get("dhcp_hostname"),
                "ip": c.get("ip"),
                "type": c.get("resolved_type") or c.get("deviceType"),
                "vendor": c.get("oui_vendor"),
                "is_ap": False,
                "online": True,
            })
    # Also search DeviceSettings (covers offline devices with a synced name)
    if not matches:
        for s in DeviceSetting.query.all():
            name = s.last_synced_name or ""
            if q in name.lower() or q_mac in (s.mac or "").upper():
                matches.append({"mac": s.mac, "name": name or None,
                                "ip": None, "type": None, "is_ap": False,
                                "online": False})
    # Also search access points (so 'garage AP' resolves the infrastructure).
    for ap_mac, ap_name in get_ap_names().items():
        if q in (ap_name or "").lower() or q_mac in ap_mac.upper():
            if not any(m["mac"].upper().replace(":", "-") == ap_mac for m in matches):
                matches.append({"mac": ap_mac, "name": ap_name, "ip": None,
                                "type": "Access Point", "is_ap": True,
                                "online": True})
    return {"matches": matches[:8], "count": len(matches)}


def _tool_count_events(args: dict) -> dict:
    qy = SyslogEvent.query.filter(SyslogEvent.received_at >= _hours_cutoff(args.get("hours", 24)))
    if args.get("mac"):
        qy = qy.filter(SyslogEvent.client_mac == args["mac"].upper().replace(":", "-"))
    if args.get("event_type"):
        qy = qy.filter(SyslogEvent.event_type == args["event_type"])
    return {"count": qy.count(),
            "window_hours": args.get("hours", 24),
            "filters": {k: args.get(k) for k in ("mac", "event_type") if args.get(k)}}


def _tool_list_events(args: dict) -> dict:
    limit = min(int(args.get("limit", 20) or 20), 50)
    qy = SyslogEvent.query.filter(SyslogEvent.received_at >= _hours_cutoff(args.get("hours", 24)))
    if args.get("mac"):
        qy = qy.filter(SyslogEvent.client_mac == args["mac"].upper().replace(":", "-"))
    if args.get("event_type"):
        qy = qy.filter(SyslogEvent.event_type == args["event_type"])
    rows = qy.order_by(SyslogEvent.id.desc()).limit(limit).all()
    return {"events": [{
        "at": r.received_at, "type": r.event_type, "severity": r.severity,
        "mac": r.client_mac, "ssid": r.ssid, "ap": r.device_name,
        "message": (r.message or "")[:200],
    } for r in rows], "count": len(rows)}


def _tool_status_of_clients(args: dict) -> dict:
    from sqlalchemy import func
    cutoff = _hours_cutoff(args.get("hours", 24))
    problem_types = ["auth_failed", "deauth", "client_disconnect", "reconnect"]
    rows = db.session.query(
        SyslogEvent.client_mac, func.count(SyslogEvent.id).label("n")
    ).filter(
        SyslogEvent.received_at >= cutoff,
        SyslogEvent.event_type.in_(problem_types),
        SyslogEvent.client_mac.isnot(None),
    ).group_by(SyslogEvent.client_mac).order_by(
        func.count(SyslogEvent.id).desc()).limit(10).all()
    out = []
    for mac, n in rows:
        ident = _device_identity(mac)
        # Break down what kinds of problems
        breakdown = dict(db.session.query(
            SyslogEvent.event_type, func.count(SyslogEvent.id)
        ).filter(
            SyslogEvent.received_at >= cutoff,
            SyslogEvent.client_mac == mac,
            SyslogEvent.event_type.in_(problem_types),
        ).group_by(SyslogEvent.event_type).all())
        out.append({"mac": mac, "name": ident["name"],
                    "problem_events": n, "breakdown": breakdown})
    return {"clients_with_issues": out, "window_hours": args.get("hours", 24)}


def _tool_troubleshoot_device(args: dict) -> dict:
    from sqlalchemy import func
    mac = (args.get("mac") or "").upper().replace(":", "-")
    if not mac:
        return {"error": "mac required"}
    cutoff = _hours_cutoff(args.get("hours", 24))
    ident = _device_identity(mac)
    by_type = dict(db.session.query(
        SyslogEvent.event_type, func.count(SyslogEvent.id)
    ).filter(
        SyslogEvent.received_at >= cutoff, SyslogEvent.client_mac == mac
    ).group_by(SyslogEvent.event_type).all())
    recent = SyslogEvent.query.filter(
        SyslogEvent.received_at >= cutoff, SyslogEvent.client_mac == mac
    ).order_by(SyslogEvent.id.desc()).limit(15).all()
    return {
        "device": ident,
        "event_breakdown": by_type,
        "recent_events": [{
            "at": r.received_at, "type": r.event_type, "severity": r.severity,
            "ssid": r.ssid, "ap": r.device_name, "message": (r.message or "")[:160],
        } for r in recent],
        "window_hours": args.get("hours", 24),
    }


def _tool_roaming_of(args: dict) -> dict:
    """Roaming history over a window: ordered AP-hop sequence (oldest→newest)
    with resolved AP names, a per-AP visit tally, and an optional timeline
    chart. Degrades gracefully when no roam events were captured."""
    from datetime import datetime, timezone
    mac = (args.get("mac") or "").upper().replace(":", "-")
    if not mac:
        return {"error": "mac required"}
    hours = float(args.get("hours") or 24)
    cutoff = _hours_cutoff(hours)
    # Oldest→newest so the hop sequence reads chronologically.
    rows = SyslogEvent.query.filter(
        SyslogEvent.received_at >= cutoff,
        SyslogEvent.client_mac == mac,
        SyslogEvent.event_type.in_(["roamed", "roaming"]),
    ).order_by(SyslogEvent.id.asc()).limit(200).all()

    ident = _device_identity(mac)
    if not rows:
        return {
            "device": ident,
            "roam_count": 0,
            "window_hours": hours,
            "note": ("No roaming events were captured for this device in the "
                     "window. Omada may not be exporting roam/roaming events "
                     "over syslog — the data here is mostly traffic-flow and "
                     "DHCP. Roaming visibility needs the controller's client "
                     "roaming events enabled in syslog export."),
        }

    # Build the hop sequence and per-AP tally with resolved AP names.
    hops = []
    ap_tally: dict = {}
    chart_labels, chart_values = [], []
    for r in rows:
        ap_mac = r.device_name
        ap_name = resolve_ap(ap_mac) or ap_mac
        hops.append({"at": r.received_at, "ap_mac": ap_mac, "ap": ap_name,
                     "ssid": r.ssid})
        ap_tally[ap_name] = ap_tally.get(ap_name, 0) + 1

    # Count transitions (an actual move between two different APs).
    transitions = sum(
        1 for i in range(1, len(hops)) if hops[i]["ap_mac"] != hops[i - 1]["ap_mac"]
    )

    result = {
        "device": ident,
        "roam_count": len(rows),
        "transitions": transitions,
        "aps_visited": sorted(ap_tally.items(), key=lambda kv: kv[1], reverse=True),
        "hops": hops[-50:],   # cap returned hops for token sanity
        "window_hours": hours,
    }

    # Optional timeline chart: roam events bucketed over the window.
    if args.get("chart"):
        minutes = hours * 60
        bucket_sec = max(300, int((minutes * 60) // 24))
        counts: dict = {}
        for r in rows:
            try:
                ts = datetime.strptime(r.received_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                continue
            epoch = int(ts.timestamp())
            b = epoch - (epoch % bucket_sec)
            counts[b] = counts.get(b, 0) + 1
        for b in sorted(counts):
            lbl = datetime.fromtimestamp(b, tz=timezone.utc).astimezone().strftime(
                "%m-%d %H:%M" if hours > 36 else "%H:%M")
            chart_labels.append(lbl)
            chart_values.append(counts[b])
        if chart_labels:
            result["chart"] = {
                "type": "line",
                "title": f"Roam events — {ident['name'] or mac}",
                "labels": chart_labels,
                "values": chart_values,
                "window_hours": hours,
            }
    return result


def _tool_aggregate_events(args: dict) -> dict:
    """One-shot aggregation: group events and return ranked buckets with counts,
    percentages, and per-hour rates. Optionally emits a chart spec the frontend
    renders. Replaces the brute-force pattern of many count_events calls."""
    from sqlalchemy import func
    group_by = (args.get("group_by") or "client").strip()
    hours = float(args.get("hours") or 1)
    cutoff = _hours_cutoff(hours)
    limit = min(int(args.get("limit", 8) or 8), 20)

    base = SyslogEvent.query.filter(SyslogEvent.received_at >= cutoff)
    if args.get("event_type"):
        base = base.filter(SyslogEvent.event_type == args["event_type"])
    if args.get("mac"):
        base = base.filter(SyslogEvent.client_mac == args["mac"].upper().replace(":", "-"))
    total = base.count()

    def _pct(n):
        return round(n / total * 100, 1) if total else 0.0

    def _rate(n):
        return round(n / hours, 1) if hours else float(n)

    labels, values, buckets = [], [], []

    if group_by == "time":
        # Counts per time bucket (~30 buckets across the window).
        from datetime import datetime, timezone
        minutes = hours * 60
        bucket_sec = max(60, int((minutes * 60) // 30))
        rows = db.session.query(SyslogEvent.received_at).filter(
            SyslogEvent.received_at >= cutoff)
        if args.get("event_type"):
            rows = rows.filter(SyslogEvent.event_type == args["event_type"])
        if args.get("mac"):
            rows = rows.filter(SyslogEvent.client_mac == args["mac"].upper().replace(":", "-"))
        counts: dict = {}
        for (received_at,) in rows.all():
            try:
                ts = datetime.strptime(received_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                continue
            epoch = int(ts.timestamp())
            b = epoch - (epoch % bucket_sec)
            counts[b] = counts.get(b, 0) + 1
        for b in sorted(counts):
            hhmm = datetime.fromtimestamp(b, tz=timezone.utc).astimezone().strftime("%H:%M")
            labels.append(hhmm)
            values.append(counts[b])
            buckets.append({"label": hhmm, "count": counts[b]})
        chart_default = "line"
    else:
        # client | ap | event_type ranking.
        col = {
            "client": SyslogEvent.client_mac,
            "ap": SyslogEvent.device_name,
            "event_type": SyslogEvent.event_type,
        }.get(group_by, SyslogEvent.client_mac)
        q = base.with_entities(col, func.count(SyslogEvent.id)).filter(
            col.isnot(None)).group_by(col).order_by(func.count(SyslogEvent.id).desc()).limit(limit)
        for key, n in q.all():
            label = key
            extra = {}
            if group_by == "client":
                ident = _device_identity(key)
                label = ident["name"] or key
                extra = {"name": ident["name"], "type": ident["type"], "is_ap": ident["is_ap"]}
            elif group_by == "ap":
                ap_name = resolve_ap(key)
                label = ap_name or key
                extra = {"name": ap_name, "is_ap": True}
            elif group_by == "event_type":
                label = key or "unknown"
            buckets.append({"key": key, "label": label, "count": n,
                            "pct": _pct(n), "per_hour": _rate(n), **extra})
            labels.append(label)
            values.append(n)
        chart_default = "doughnut" if group_by == "event_type" else "bar"

    result = {
        "group_by": group_by,
        "window_hours": hours,
        "total_events": total,
        "buckets": buckets,
    }

    # Optional chart spec — the frontend turns this into a Chart.js chart.
    if args.get("chart") and labels:
        ctype = (args.get("chart_type") or chart_default).strip()
        if ctype not in ("bar", "line", "doughnut"):
            ctype = chart_default
        title_map = {
            "client": "Busiest devices", "ap": "Busiest access points",
            "event_type": "Events by type", "time": "Events over time",
        }
        result["chart"] = {
            "type": ctype,
            "title": title_map.get(group_by, "Event aggregation"),
            "labels": labels,
            "values": values,
            "window_hours": hours,
        }
    return result


def _execute_chat_tool(name: str, args: dict, clients: list) -> dict:
    """Dispatch a Gemini function call to its executor."""
    try:
        if name == "find_device":
            return _tool_find_device(args, clients)
        if name == "count_events":
            return _tool_count_events(args)
        if name == "list_events":
            return _tool_list_events(args)
        if name == "status_of_clients":
            return _tool_status_of_clients(args)
        if name == "troubleshoot_device":
            return _tool_troubleshoot_device(args)
        if name == "roaming_of":
            return _tool_roaming_of(args)
        if name == "aggregate_events":
            return _tool_aggregate_events(args)
        return {"error": f"unknown tool {name}"}
    except Exception as exc:
        log.exception("chat tool %s failed", name)
        return {"error": str(exc)}


@app.route("/api/chat", methods=["POST"])
def chat():
    """Multi-turn chat about the network.

    Body:
      {
        "scope":    "all" | "<MAC>",
        "messages": [{"role": "user"|"assistant", "content": "..."}, ...],
        "model":    optional gemini model id (defaults to active)
      }

    Returns:
      {"reply": "...", "model": "gemini-...", "scope": "..."}
    """
    if not GEMINI_API_KEY:
        return jsonify({"error": "No Gemini API key configured. "
                                  "Set it in the Configuration view."}), 400
    data = request.json or {}
    scope = (data.get("scope") or "all").strip() or "all"
    messages = data.get("messages") or []
    if not messages:
        return jsonify({"error": "no messages provided"}), 400
    model_id = (data.get("model") or "").strip() or get_active_gemini_model()
    if model_id not in GEMINI_MODEL_IDS:
        return jsonify({"error": f"unknown model: {model_id}"}), 400

    # Pull current client list (same data the UI sees). Reuse the cached
    # /api/clients dataset if possible by going through fetch+enrich.
    try:
        raw_clients = omada.list_clients()
    except Exception as exc:
        log.exception("chat: failed to fetch clients")
        return jsonify({"error": f"Could not fetch client list: {exc}"}), 502

    enriched = _enrich_clients_for_display(raw_clients)
    system_prompt = _build_chat_system_prompt(scope, enriched)

    # Convert OpenAI-style message roles to Gemini's user/model roles
    contents = []
    for m in messages:
        role = m.get("role")
        text = (m.get("content") or "").strip()
        if not text:
            continue
        if role == "assistant":
            contents.append({"role": "model", "parts": [{"text": text}]})
        else:
            contents.append({"role": "user", "parts": [{"text": text}]})

    if not contents or contents[-1]["role"] != "user":
        return jsonify({"error": "last message must be from the user"}), 400

    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{model_id}:generateContent")

    # Tool-using loop: Gemini may call our Marvis-style query tools to read
    # real data before answering. We run up to a few rounds of
    # call → execute → feed-back until it produces a text answer.
    tool_trace = []
    charts = []          # chart specs harvested from aggregate_events results
    reply = None
    MAX_ROUNDS = 5
    try:
        for _round in range(MAX_ROUNDS):
            payload = {
                "systemInstruction": {"parts": [{"text": system_prompt}]},
                "contents": contents,
                "tools": CHAT_TOOLS,
                "generationConfig": {"temperature": 0.4, "maxOutputTokens": 4096},
            }
            r = requests.post(url, params={"key": GEMINI_API_KEY},
                              json=payload, timeout=60)
            r.raise_for_status()
            body = r.json()
            cand = body["candidates"][0]
            parts = cand.get("content", {}).get("parts", [])

            # Collect any function calls in this turn.
            calls = [p["functionCall"] for p in parts if "functionCall" in p]
            if not calls:
                # No tool call → this is the final text answer.
                reply = "".join(p.get("text", "") for p in parts).strip()
                break

            # Append the model's tool-call turn, then execute each call and
            # append the results as a function-response turn.
            contents.append({"role": "model", "parts": parts})
            response_parts = []
            for call in calls:
                fname = call.get("name")
                fargs = call.get("args", {}) or {}
                result = _execute_chat_tool(fname, fargs, enriched)
                tool_trace.append({"tool": fname, "args": fargs})
                # Harvest any chart spec so the UI can render it. We strip it
                # from what we feed back to Gemini (it doesn't need the raw
                # arrays — it has the buckets — and it keeps the payload lean).
                if isinstance(result, dict) and result.get("chart"):
                    charts.append(result.pop("chart"))
                response_parts.append({
                    "functionResponse": {
                        "name": fname,
                        "response": {"result": result},
                    }
                })
            contents.append({"role": "user", "parts": response_parts})
        else:
            # Loop exhausted without a text answer.
            reply = ("I gathered the data but couldn't compose a final answer "
                     "in time — try narrowing the question.")
    except requests.HTTPError as exc:
        detail = exc.response.text if exc.response is not None else str(exc)
        log.error("chat: Gemini HTTP error: %s", detail)
        return jsonify({"error": f"Gemini API error: {detail[:300]}"}), 502
    except (KeyError, IndexError) as exc:
        return jsonify({"error": f"Unexpected Gemini response: {exc}"}), 502
    except Exception as exc:
        log.exception("chat: Gemini call failed")
        return jsonify({"error": str(exc)}), 502

    if not reply:
        reply = "(no response)"

    # Build a human-readable scope label for the UI status line. For "all",
    # include the device count; for per-MAC, find the device's current name.
    if scope == "all":
        scope_label = f"all {len(enriched)} clients"
    else:
        target = next((c for c in enriched if c.get("mac") == scope), None)
        if target:
            scope_label = target.get("name") or target.get("dhcp_hostname") or scope
        else:
            scope_label = scope

    return jsonify({
        "reply":       reply,
        "model":       model_id,
        "scope":       scope,
        "scope_label": scope_label,
        "tools_used":  tool_trace,
        "charts":      charts,
    })


@app.route("/api/harmonize_preview", methods=["POST"])
def harmonize_preview():
    """Compute proposed harmonization without applying. Returns clusters with
    Gemini's proposed short_names per device. Body params:
      max_clusters: int — only process N clusters (default all)
    """
    data = request.json or {}
    max_clusters = data.get("max_clusters")

    try:
        raw_clients = omada.list_clients()
    except Exception as exc:
        return jsonify({"error": str(exc), "clusters": []}), 502

    settings_by_mac = {s.mac: s for s in DeviceSetting.query.all()}
    clusters = cluster_devices_for_harmonization(raw_clients, settings_by_mac)

    if not clusters:
        return jsonify({
            "clusters": [],
            "message": ("No clusters with 2+ AI-named devices found. Run "
                        "Scan Unidentified first so devices have AI analyses."),
        })

    # Sort clusters by size descending, so the most useful go first
    sorted_keys = sorted(clusters.keys(), key=lambda k: -len(clusters[k]))
    if max_clusters:
        sorted_keys = sorted_keys[:int(max_clusters)]

    result_clusters = []
    for key in sorted_keys:
        members = clusters[key]
        try:
            proposals = harmonize_cluster_with_gemini(key, members)
            proposals_by_mac = {p["mac"]: p for p in proposals}
            merged = []
            for m in members:
                p = proposals_by_mac.get(m["mac"])
                if p:
                    proposed_name = p["proposed_short_name"].strip()
                    merged.append({
                        "mac": m["mac"],
                        "current_short_name": m["current_short_name"],
                        "proposed_short_name": proposed_name,
                        "reasoning": p.get("reasoning", ""),
                        "changed": proposed_name != m["current_short_name"],
                    })
                else:
                    merged.append({
                        "mac": m["mac"],
                        "current_short_name": m["current_short_name"],
                        "proposed_short_name": m["current_short_name"],
                        "reasoning": "AI did not return a proposal for this device",
                        "changed": False,
                    })
            result_clusters.append({
                "key": key,
                "name": key.title(),
                "size": len(members),
                "changes_count": sum(1 for x in merged if x["changed"]),
                "members": merged,
            })
        except Exception as exc:
            log.exception("Failed to harmonize cluster %s", key)
            result_clusters.append({
                "key": key,
                "name": key.title(),
                "size": len(members),
                "error": str(exc)[:200],
                "changes_count": 0,
                "members": [{
                    "mac": m["mac"],
                    "current_short_name": m["current_short_name"],
                    "proposed_short_name": m["current_short_name"],
                    "reasoning": "(call failed)",
                    "changed": False,
                } for m in members],
            })

    return jsonify({
        "clusters": result_clusters,
        "total_clusters_found": len(clusters),
        "total_clusters_returned": len(result_clusters),
    })


@app.route("/api/harmonize_apply", methods=["POST"])
def harmonize_apply():
    """Apply approved harmonization updates. Body:
      updates: [{mac, new_short_name}, ...]
    Updates each device's stored ai_analysis.short_name. Does NOT push to Omada;
    user runs Sync All Mismatched afterward to commit names.
    """
    data = request.json or {}
    updates = data.get("updates", [])
    if not updates:
        return jsonify({"applied": 0, "errors": []})

    applied = 0
    errors: list[dict] = []
    for u in updates:
        mac = u.get("mac")
        new_name = (u.get("new_short_name") or "").strip()
        if not mac or not new_name:
            errors.append({"mac": mac, "error": "missing mac or new_short_name"})
            continue
        setting = get_setting(mac)
        if not setting or not setting.ai_analysis:
            errors.append({"mac": mac, "error": "no existing AI analysis to update"})
            continue
        try:
            ai_data = json.loads(setting.ai_analysis)
            ai_data["short_name"] = new_name
            ai_data["_harmonized_at"] = iso_now()
            setting.ai_analysis = json.dumps(ai_data)
            db.session.add(setting)
            applied += 1
        except Exception as exc:
            errors.append({"mac": mac, "error": str(exc)[:200]})

    db.session.commit()
    return jsonify({"applied": applied, "errors": errors})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8082, debug=True)
