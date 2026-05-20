"""Passive DHCP + mDNS fingerprint capture via TZSP forwarding.

Instead of sniffing on a local interface (awkward inside Docker), this
listens for TZSP-encapsulated packets forwarded from an upstream sniffer
like MikroTik's Tools > Packet Sniffer > Streaming. The source filters
DHCP and mDNS traffic and pushes it to UDP port 37008 here.

Why mDNS matters: devices voluntarily announce what services they provide
(_hap._tcp = HomeKit, _googlecast._tcp = Chromecast, _airplay._tcp = Apple,
_printer._tcp = printer, etc.). Per Mir et al. 2025 (Internet of Things 34,
101758, Table 3), mDNS is rated HIGH-efficiency for IoT device fingerprinting
— stronger than IP/port pairs and on par with DHCP fingerprinting itself.

MikroTik setup:
  /tool sniffer set streaming-enabled=yes \\
      streaming-server=<this-host>:37008 \\
      filter-ip-protocol=udp filter-port=bootps,bootpc,mdns
  /tool sniffer start

docker-compose:
  ports:
    - "<host-ip>:37008:37008/udp"

No raw sockets, no NET_RAW capability, no host networking needed.

TZSP packet format:
  Header (4 bytes): version(1) type(1) encap_proto(2 BE)
  Tagged fields (variable TLV, terminated by TAG_END=0x01)
  Payload: original Ethernet frame (if encap_proto==1)

The class is still named DHCPCapture for backward compatibility with
older app.py imports; conceptually it's now a NetworkCapture handling
both DHCP and mDNS. The on_mdns callback is optional — if not passed,
mDNS frames are counted but not forwarded.
"""

from __future__ import annotations

import logging
import os
import socket
import struct
import threading
from datetime import datetime, timezone
from typing import Callable, Optional

log = logging.getLogger(__name__)

# DHCP callback: (mac_dash, fingerprint, vendor_class, hostname) -> None
PacketCallback = Callable[[str, Optional[str], Optional[str], Optional[str]], None]

# mDNS callback: (mac_dash, services, txt_records, instance_names) -> None
# services: list of service types like ["_hap._tcp", "_airplay._tcp"]
# txt_records: dict of {key: value} from any TXT records seen in this packet
# instance_names: list of human-readable instance labels like
#   ["Living Room TV", "Tim's iPhone"]
MdnsCallback = Callable[[str, list, dict, list], None]

TZSP_END_TAG = 0x01
TZSP_PADDING_TAG = 0x00
TZSP_ENCAP_ETHERNET = 0x0001


def parse_tzsp(data: bytes) -> Optional[bytes]:
    """Strip the TZSP wrapper and return the encapsulated Ethernet frame.
    Returns None if the packet isn't a valid TZSP/Ethernet payload."""
    if len(data) < 4:
        return None
    version, _msg_type, proto = struct.unpack("!BBH", data[:4])
    if version != 1 or proto != TZSP_ENCAP_ETHERNET:
        return None

    offset = 4
    while offset < len(data):
        tag = data[offset]
        offset += 1
        if tag == TZSP_END_TAG:
            return data[offset:]
        if tag == TZSP_PADDING_TAG:
            continue
        if offset >= len(data):
            return None
        length = data[offset]
        offset += 1 + length
    return None


class DHCPCapture:
    """TZSP listener that decodes both DHCP and mDNS from forwarded Ethernet.

    Despite the class name (kept for backward compatibility), this handles
    both protocols. Pass on_mdns=None to disable mDNS dispatch.
    """

    def __init__(self, port, on_packet: PacketCallback,
                 on_mdns: Optional[MdnsCallback] = None):
        try:
            self.port = int(port)
        except (TypeError, ValueError) as exc:
            raise TypeError(
                f"DHCPCapture port must be an integer, got {port!r}. "
                f"If you're seeing this in Docker, check that app.py is "
                f"passing DHCP_CAPTURE_PORT (not the old DHCP_CAPTURE_INTERFACE)."
            ) from exc
        self.on_packet = on_packet
        self.on_mdns = on_mdns
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

        self.packets_received = 0
        self.tzsp_packets = 0
        self.dhcp_packets = 0
        self.fingerprints_emitted = 0
        self.mdns_packets = 0
        self.mdns_records_emitted = 0

        self.last_packet_at: Optional[str] = None
        self.last_packet_mac: Optional[str] = None
        self.last_source_ip: Optional[str] = None
        self.last_mdns_at: Optional[str] = None
        self.last_mdns_mac: Optional[str] = None
        self.error: Optional[str] = None
        self.running = False
        self.started_at: Optional[str] = None

    def start(self) -> bool:
        if os.environ.get("WERKZEUG_RUN_MAIN") == "false":
            log.info("Skipping TZSP listener in reloader watcher process")
            return False

        try:
            import scapy.all  # noqa: F401
        except ImportError as exc:
            self.error = f"scapy not installed ({exc}). Run: pip install scapy"
            log.warning(self.error)
            return False

        if self._thread and self._thread.is_alive():
            return True

        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="tzsp-listener"
        )
        self._thread.start()
        self.started_at = _iso_now()
        return True

    def stop(self) -> None:
        self._stop.set()

    def status(self) -> dict:
        scapy_ok = self.error is None or "scapy not installed" not in (self.error or "")
        return {
            "mode": "tzsp",
            "available": scapy_ok,
            "running": self.running,
            "listen_port": self.port,
            "packets_received": self.packets_received,
            "tzsp_packets": self.tzsp_packets,
            "dhcp_packets": self.dhcp_packets,
            "fingerprints_emitted": self.fingerprints_emitted,
            "mdns_packets": self.mdns_packets,
            "mdns_records_emitted": self.mdns_records_emitted,
            "last_packet_at": self.last_packet_at,
            "last_packet_mac": self.last_packet_mac,
            "last_source_ip": self.last_source_ip,
            "last_mdns_at": self.last_mdns_at,
            "last_mdns_mac": self.last_mdns_mac,
            "started_at": self.started_at,
            "error": self.error,
        }

    def _run(self) -> None:
        # Importing scapy.all (not just scapy.layers.l2) registers all the
        # layer bindings so Ether(bytes) recurses into IP/UDP/BOOTP/DHCP/DNS
        # instead of stopping at Ether/Raw.
        from scapy.all import Ether

        self.running = True
        self.error = None
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", self.port))
            sock.settimeout(1.0)
            log.info("TZSP listener bound to 0.0.0.0:%d (DHCP + mDNS)", self.port)
        except OSError as exc:
            self.error = (
                f"Cannot bind UDP/{self.port}: {exc}. "
                f"Check that no other service is using it and that the port "
                f"is mapped through Docker."
            )
            log.error(self.error)
            self.running = False
            return

        try:
            while not self._stop.is_set():
                try:
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError as exc:
                    log.error("TZSP recv error: %s", exc)
                    continue

                self.packets_received += 1
                self.last_source_ip = addr[0]

                frame_bytes = parse_tzsp(data)
                if frame_bytes is None:
                    continue
                self.tzsp_packets += 1

                try:
                    pkt = Ether(frame_bytes)
                except Exception:
                    log.exception("Failed to parse inner Ethernet frame")
                    continue

                self._handle_packet(pkt)
        finally:
            try:
                sock.close()
            except Exception:
                pass
            self.running = False
            log.info("TZSP listener stopped")

    def _handle_packet(self, pkt) -> None:
        """Dispatch parsed Ethernet frame to DHCP or mDNS handler based on
        the UDP destination port. Order matters: we check DHCP first because
        it has a distinct scapy DHCP layer; mDNS falls back to UDP/5353
        recognition with DNS payload."""
        from scapy.all import DHCP, UDP

        if pkt.haslayer(DHCP):
            self._handle_dhcp(pkt)
            return

        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            # mDNS uses port 5353 on both sides for queries and responses.
            if udp.sport == 5353 or udp.dport == 5353:
                self._handle_mdns(pkt)

    def _handle_dhcp(self, pkt) -> None:
        from scapy.all import DHCP, Ether

        msg_type = None
        fingerprint: Optional[str] = None
        vendor_class: Optional[str] = None
        hostname: Optional[str] = None

        for opt in pkt[DHCP].options:
            if not isinstance(opt, tuple) or len(opt) < 2:
                continue
            key, val = opt[0], opt[1]
            if key == "message-type":
                msg_type = val
            elif key == "param_req_list":
                if isinstance(val, (list, tuple)):
                    fingerprint = ",".join(str(int(x)) for x in val)
            elif key == "vendor_class_id":
                vendor_class = _decode_str(val)
            elif key == "hostname":
                hostname = _decode_str(val)

        # Client messages only: 1=DISCOVER, 3=REQUEST, 8=INFORM.
        if msg_type not in (1, 3, 8):
            return
        if not fingerprint and not vendor_class:
            return

        self.dhcp_packets += 1
        mac = pkt[Ether].src.upper().replace(":", "-")
        self.last_packet_at = _iso_now()
        self.last_packet_mac = mac

        try:
            self.on_packet(mac, fingerprint, vendor_class, hostname)
            self.fingerprints_emitted += 1
        except Exception:
            log.exception("on_packet callback failed for %s", mac)

    def _handle_mdns(self, pkt) -> None:
        """Extract mDNS service types, TXT records, and instance names from
        the DNS payload of an mDNS packet. mDNS is just DNS on UDP/5353, often
        broadcast to 224.0.0.251."""
        from scapy.all import DNS, Ether

        self.mdns_packets += 1
        if not pkt.haslayer(DNS):
            return
        if self.on_mdns is None:
            return

        dns = pkt[DNS]
        services: set[str] = set()
        txt_records: dict[str, str] = {}
        instance_names: list[str] = []

        # Walk every record in answers (an) + authority (ns) + additional (ar).
        # Each record carries something useful:
        #   PTR @ _foo._tcp.local → instance._foo._tcp.local  (service type ptr)
        #   SRV @ instance._foo._tcp.local → target.local port  (port + host)
        #   TXT @ instance._foo._tcp.local → key=value, key=value
        #   A @ host.local → 192.168.x.y
        for section_attr, count_attr in (("an", "ancount"),
                                          ("ns", "nscount"),
                                          ("ar", "arcount")):
            count = getattr(dns, count_attr, 0) or 0
            records = getattr(dns, section_attr, None)
            if not records:
                continue
            for i in range(count):
                try:
                    rr = records[i] if hasattr(records, "__getitem__") else records
                except (IndexError, TypeError):
                    continue
                rrname = _decode_str(getattr(rr, "rrname", b""))
                rtype = getattr(rr, "type", None)
                rdata = getattr(rr, "rdata", None)

                if not rrname:
                    continue
                rrname_lc = rrname.rstrip(".").lower()

                # Service type discovery: PTR records (type 12) whose owner
                # name looks like _service._proto.local — their rdata point
                # to instance names of that service type.
                if rtype == 12 and _is_service_type(rrname_lc):
                    services.add(_service_type_short(rrname_lc))
                    instance = _decode_str(rdata)
                    if instance:
                        bare = _instance_label(instance, rrname_lc)
                        if bare:
                            instance_names.append(bare)

                # Some devices announce their service type in the rdata of
                # the meta-PTR _services._dns-sd._udp.local — capture those
                # too. The rdata IS the service type in that case.
                if rtype == 12 and "_services._dns-sd._udp" in rrname_lc:
                    rdata_str = _decode_str(rdata) or ""
                    rdata_lc = rdata_str.rstrip(".").lower()
                    if _is_service_type(rdata_lc):
                        services.add(_service_type_short(rdata_lc))

                # TXT records (type 16) carry key=value pairs. Apple and most
                # vendors stuff model number, firmware, friendly name into
                # these — high-signal data for identification.
                if rtype == 16:
                    txt_kv = _parse_txt_rdata(rdata)
                    for k, v in txt_kv.items():
                        # Last-write-wins is fine; multiple TXTs from the
                        # same flight tend to agree.
                        txt_records[k] = v
                    label = _instance_from_name(rrname_lc)
                    if label:
                        instance_names.append(label)

                # SRV records (type 33) confirm service hosting; the instance
                # label is the rrname.
                if rtype == 33:
                    label = _instance_from_name(rrname_lc)
                    if label:
                        instance_names.append(label)

        if not services and not txt_records and not instance_names:
            return

        mac = pkt[Ether].src.upper().replace(":", "-")
        self.last_mdns_at = _iso_now()
        self.last_mdns_mac = mac

        try:
            self.on_mdns(
                mac,
                sorted(services),
                txt_records,
                # Dedupe instance names case-insensitively, preserving the
                # first-seen casing — PTR rdata usually has the canonical
                # mixed-case form, TXT rrnames are lowercased.
                _dedupe_ci(instance_names),
            )
            self.mdns_records_emitted += 1
        except Exception:
            log.exception("on_mdns callback failed for %s", mac)


# --------------------- mDNS name parsing helpers ---------------------

def _is_service_type(name_lc: str) -> bool:
    """Match service-type names like '_hap._tcp.local' or '_googlecast._tcp.local'.
    Excludes the meta '_services._dns-sd._udp' which is a discovery aggregator,
    not a real service type."""
    if "_services._dns-sd" in name_lc:
        return False
    parts = name_lc.split(".")
    # Need at least: ['_service', '_tcp|_udp', 'local'] = 3 parts after split
    if len(parts) < 3:
        return False
    if not parts[0].startswith("_"):
        return False
    if parts[1] not in ("_tcp", "_udp"):
        return False
    return True


def _service_type_short(name_lc: str) -> str:
    """Trim '_foo._tcp.local' → '_foo._tcp'."""
    parts = name_lc.rstrip(".").split(".")
    if len(parts) >= 3 and parts[-1] == "local":
        return ".".join(parts[:-1])
    return name_lc


def _instance_label(instance: str, service_type_lc: str) -> Optional[str]:
    """Strip the service-type suffix off an instance name.
    'Living Room TV._airplay._tcp.local.' + '_airplay._tcp.local'
     → 'Living Room TV'"""
    if not instance:
        return None
    inst_lc = instance.rstrip(".").lower()
    if inst_lc.endswith(service_type_lc):
        suffix_len = len(service_type_lc) + 1  # +1 for the dot separator
        label = instance.rstrip(".")[: -suffix_len].rstrip(".")
        return label or None
    return instance.rstrip(".") or None


def _instance_from_name(name_lc: str) -> Optional[str]:
    """Pull the human-readable instance label off a name like
    'Tim\\032iPhone._companion-link._tcp.local'."""
    parts = name_lc.rstrip(".").split(".")
    if len(parts) >= 3 and parts[-1] == "local" and parts[-2] in ("_tcp", "_udp"):
        # Everything before the service-type suffix is the instance name.
        label = ".".join(parts[:-3])
        # mDNS uses \032 for spaces in some implementations.
        return label.replace("\\032", " ").replace("\\ ", " ") or None
    return None


def _parse_txt_rdata(rdata) -> dict[str, str]:
    """TXT rdata is a list of length-prefixed strings. Each string is usually
    key=value but sometimes just a flag (no equals). scapy hands us either
    bytes (raw) or a list."""
    out: dict[str, str] = {}
    if rdata is None:
        return out
    items: list[bytes] = []
    if isinstance(rdata, (list, tuple)):
        for r in rdata:
            if isinstance(r, bytes):
                items.append(r)
            elif isinstance(r, str):
                items.append(r.encode("utf-8", errors="replace"))
    elif isinstance(rdata, bytes):
        # Single length-prefixed string, or the raw rdata not yet split.
        # We try a best-effort split on the length-prefix encoding.
        i = 0
        while i < len(rdata):
            ln = rdata[i]
            i += 1
            if i + ln > len(rdata):
                break
            items.append(rdata[i:i + ln])
            i += ln
    for item in items:
        try:
            s = item.decode("utf-8", errors="replace")
        except Exception:
            continue
        if "=" in s:
            k, _, v = s.partition("=")
            k = k.strip().lower()
            v = v.strip()
            if k and v:
                out[k] = v
    return out


def _dedupe_ci(items: list) -> list:
    """Deduplicate strings case-insensitively, preserving order and the
    casing of the first occurrence (which is usually the canonical form
    from PTR rdata rather than the lowercased version from TXT rrnames)."""
    seen: set = set()
    out: list = []
    for x in items:
        key = x.lower() if isinstance(x, str) else x
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out


def _decode_str(val) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8", errors="replace").rstrip("\x00").strip() or None
        except Exception:
            return repr(val)
    return str(val).strip() or None


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class LocalSniffer(DHCPCapture):
    """Sniff DHCP + mDNS directly from a host network interface using a
    BPF-filtered scapy.sniff() loop, instead of decoding TZSP wrappers.

    Required when running on a network where the upstream router can't or
    won't forward mDNS multicast via TZSP — most common when:
      • Switches do IGMP snooping that filters 224.0.0.251 link-local
      • Router and devices are on different VLANs without bridge_mcast
      • The user doesn't have a TZSP-capable router at all

    Operationally this requires:
      • container running with `network_mode: host` (Docker bridge does not
        forward multicast traffic via -p port mappings, only unicast to
        the host's IP)
      • `cap_add: [NET_RAW]` capability so AF_PACKET raw sockets can be
        opened by an unprivileged container
      • libpcap installed in the image (already pulled in by scapy)

    The container coexists fine with a host-side avahi-daemon — sniff uses
    AF_PACKET raw sockets at L2, which doesn't bind to UDP/5353, so there's
    no port conflict."""

    def __init__(self, iface: str, on_packet: PacketCallback,
                 on_mdns: Optional[MdnsCallback] = None):
        # Parent expects port; we don't use it in local mode but pass 0 so
        # the type contract is satisfied. status() reports listen_port=0.
        super().__init__(port=0, on_packet=on_packet, on_mdns=on_mdns)
        self.iface = iface

    def start(self) -> bool:
        # Re-implement start() because the parent runs _run() in its own
        # thread; we need the same plumbing but a different _run.
        if os.environ.get("WERKZEUG_RUN_MAIN") == "false":
            log.info("Skipping LocalSniffer in reloader watcher process")
            return False
        try:
            import scapy.all  # noqa: F401
        except ImportError as exc:
            self.error = f"scapy not installed ({exc}). Run: pip install scapy"
            log.warning(self.error)
            return False
        if self._thread and self._thread.is_alive():
            return True
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="local-sniffer"
        )
        self._thread.start()
        self.started_at = _iso_now()
        return True

    def status(self) -> dict:
        s = super().status()
        s["mode"] = "local"
        s["iface"] = self.iface
        return s

    def _run(self) -> None:
        from scapy.all import sniff
        from scapy.error import Scapy_Exception
        self.running = True
        log.info(f"LocalSniffer starting on iface={self.iface!r}")
        bpf_filter = "udp and (port 67 or port 68 or port 5353)"
        try:
            # First attempt: push the filter to the kernel via libpcap. This
            # is what we want — bytes that don't match are dropped before
            # they ever reach Python.
            sniff(
                iface=self.iface if self.iface else None,
                filter=bpf_filter,
                prn=self._sniff_callback,
                store=False,
                stop_filter=lambda _pkt: self._stop.is_set(),
            )
        except Scapy_Exception as exc:
            # libpcap not in the image → scapy raises Scapy_Exception with
            # message containing "libpcap is not available". Fall back to a
            # filter-less sniff and check the port in Python before doing
            # any real work. This works but is far slower on busy networks
            # because every frame round-trips into user space.
            msg = str(exc).lower()
            if "libpcap" in msg or "compile filter" in msg or "tcpdump" in msg:
                log.warning(
                    "BPF compilation failed (%s). Falling back to Python-side "
                    "port filtering. To restore kernel-level filtering, install "
                    "libpcap0.8 in the container Dockerfile.", exc
                )
                try:
                    sniff(
                        iface=self.iface if self.iface else None,
                        prn=self._sniff_callback_pyfilter,
                        store=False,
                        stop_filter=lambda _pkt: self._stop.is_set(),
                    )
                except Exception as exc2:
                    self.error = (
                        f"LocalSniffer crashed in libpcap-less fallback: {exc2}"
                    )
                    log.exception("LocalSniffer crashed in fallback path")
            else:
                self.error = f"LocalSniffer crashed: {exc}"
                log.exception("LocalSniffer crashed")
        except PermissionError as exc:
            self.error = (
                f"Permission denied opening raw socket: {exc}. "
                f"Container needs cap_add: [NET_RAW] and network_mode: host."
            )
            log.error(self.error)
        except OSError as exc:
            self.error = (
                f"Failed to open interface {self.iface!r}: {exc}. "
                f"Check CAPTURE_INTERFACE matches a real NIC inside the "
                f"container (try CAPTURE_INTERFACE='' to auto-pick)."
            )
            log.error(self.error)
        except Exception as exc:
            self.error = f"LocalSniffer crashed: {exc}"
            log.exception("LocalSniffer crashed")
        finally:
            self.running = False
            log.info("LocalSniffer stopped")

    def _sniff_callback_pyfilter(self, pkt) -> None:
        """Same end-state as _sniff_callback but cheaply drops non-relevant
        packets *before* calling the parser. Used only when BPF filtering
        isn't available (libpcap missing). Checks the UDP destination port
        first — a single attribute access on the scapy layer is much cheaper
        than the full parsing path."""
        from scapy.all import UDP
        if not pkt.haslayer(UDP):
            return
        u = pkt[UDP]
        # We accept either direction (DHCP exchanges use 67↔68; mDNS uses 5353).
        if u.sport not in (67, 68, 5353) and u.dport not in (67, 68, 5353):
            return
        self._sniff_callback(pkt)

    def _sniff_callback(self, pkt) -> None:
        """Per-packet callback. Update generic counters then dispatch to the
        same DHCP/mDNS handlers the TZSP path uses — the input is a real
        Ethernet frame off the wire, which is what the parsers expect."""
        self.packets_received += 1
        # tzsp_packets is reused as "frames seen at L2" in local mode so the
        # existing dashboard banner ("X pkts (X TZSP, X DHCP, X mDNS)") keeps
        # showing meaningful numbers. The mode flag in status() lets the UI
        # re-label as "frames" if it wants.
        self.tzsp_packets += 1
        self.last_packet_at = _iso_now()
        try:
            from scapy.all import Ether
            if pkt.haslayer(Ether):
                self.last_packet_mac = pkt[Ether].src
        except Exception:
            pass
        self._handle_packet(pkt)
