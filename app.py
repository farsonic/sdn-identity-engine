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
# Name template
# ---------------------------------------------------------------------------
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

    payload = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": contents,
        "generationConfig": {
            "temperature": 0.4,
            "maxOutputTokens": 4096,
        },
    }
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{model_id}:generateContent")
    try:
        r = requests.post(url, params={"key": GEMINI_API_KEY},
                          json=payload, timeout=60)
        r.raise_for_status()
        body = r.json()
        reply = body["candidates"][0]["content"]["parts"][0]["text"]
    except requests.HTTPError as exc:
        detail = exc.response.text if exc.response is not None else str(exc)
        log.error("chat: Gemini HTTP error: %s", detail)
        return jsonify({"error": f"Gemini API error: {detail[:300]}"}), 502
    except (KeyError, IndexError) as exc:
        return jsonify({"error": f"Unexpected Gemini response: {exc}"}), 502
    except Exception as exc:
        log.exception("chat: Gemini call failed")
        return jsonify({"error": str(exc)}), 502

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
