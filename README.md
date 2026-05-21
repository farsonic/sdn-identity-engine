# SDN Identity Engine

A self-hosted dashboard for identifying, naming, and managing every client on your TP-Link Omada-managed network. Combines DHCP fingerprinting, mDNS/Bonjour observation, Fingerbank lookups, and Gemini AI analysis to turn rows of "android-1234" and unknown MAC addresses into meaningful device names, automatically.

![dashboard](https://raw.githubusercontent.com/farsonic/sdn-identity-engine/main/docs/screenshot.png)

## What you get

- **All clients in one table** — name, MAC, IP, OS, vendor, AP/switch, DHCP fingerprint, mDNS services
- **Auto-identification** — DHCP fingerprints captured passively, looked up against Fingerbank, optionally analyzed by Gemini for a full device dossier
- **Naming policy** — define a template (e.g. `{type}-{vendor}-{lastoctet}`), apply across the fleet, push back to Omada
- **Marvis-style AIOps chatbot** — ask questions in plain English and Gemini answers from your *real* event data, not guesses. It calls structured query tools under the hood (find a device, count events, rank top talkers, troubleshoot, roaming history) and shows you which tools it ran. "How many times did my iPad disconnect today?" → it resolves the device, counts the actual events, and answers grounded in the number.
- **Charts in chat** — when the answer is a ranking, distribution, or trend, the assistant draws an inline chart (top talkers, event-type breakdown, activity over time)
- **Syslog ingestion + network-health briefing** — receive your Omada controller's syslog, store it, visualize it (timeline, top talkers, event types, all time-windowed), and get an on-demand Marvis-style briefing: top issues, flapping devices, repeated auth failures, root-cause hypotheses, recommended actions
- **Access-point awareness** — AP MACs in flow logs are resolved to their Omada names (so "rumpus" and "hallway" appear instead of bare MACs) and clearly distinguished from client devices everywhere they show up
- **Traffic-flow noise control** — Omada's high-volume firewall/flow logging can be dropped at ingest with one toggle, keeping the event store full of meaningful lifecycle events
- **No upstream router cooperation needed** — sniffs DHCP and mDNS directly from the host's NIC

## Prerequisites

- A Linux host on the same subnet as the devices you want to identify
- Docker + docker-compose installed
- A TP-Link Omada controller (v5.x or later, software or hardware) reachable from this host
- For multicast (mDNS) capture: the host must be on the same L2 broadcast domain as the devices. Single-subnet home networks: ✓. Multi-VLAN setups: capture per-VLAN or use a SPAN port.

> **macOS / Windows users:** Docker Desktop's `network_mode: host` doesn't actually share the host's network stack — multicast won't reach the container. Either run the container in a Linux VM with a bridged NIC, or use TZSP mode (see Alternative Capture Modes below).

## Step 1 — Get your API keys

### Omada Open API credentials (REQUIRED)

1. Log into your Omada Controller as an administrator
2. Settings (gear icon) → **Platform Integration** → **Open API**
3. Click **Add** to create a new application
4. Give it a name like "SDN Identity Engine"
5. Grant it **Read** and **Write** scope on **Site** resources
6. Copy the **Client ID** and **Client Secret** — you'll need both

You'll also need your controller's URL (e.g. `https://192.168.0.44` or `https://omada.local`). The dashboard talks to it over HTTPS; if your controller has a self-signed cert, leave TLS verification off.

### Gemini API key (OPTIONAL, recommended)

Unlocks the ✨ AI Analyze button, 💬 Chat panel, and 🪄 Harmonize Names tool. Generous free tier.

1. Visit https://aistudio.google.com/app/apikey
2. Click **Create API Key** → pick (or create) a Google Cloud project
3. Copy the key (starts with `AIzaSy...`)

Without this, the dashboard still works — you just won't get AI device identification or chat. Manual naming and Fingerbank lookups remain available.

### Fingerbank API key (OPTIONAL, recommended)

Maps DHCP fingerprints to device names using the community-maintained Fingerbank database. Free for personal use.

1. Sign up at https://fingerbank.org (free account)
2. Account page → **API Key** → copy

Without this, DHCP fingerprints still get captured and shown, you just won't get automatic device matching against the Fingerbank database. Gemini can often fill the gap.

## Step 2 — Deploy

Create a working directory:

```bash
mkdir -p ~/sdn-identity-engine && cd ~/sdn-identity-engine
mkdir instance     # SQLite database lives here, persists across upgrades
```

Create `docker-compose.yml`:

```yaml
services:
  sdn-identity-engine:
    image: farsonic/sdn-identity-engine:latest
    container_name: sdn-identity-engine
    network_mode: host               # required for mDNS multicast capture
    cap_add:
      - NET_RAW                       # required for raw-socket sniffing
    volumes:
      - ./instance:/app/instance      # persistent storage
    environment:
      - CAPTURE_MODE=local            # sniff this host's NIC directly
      - PYTHONUNBUFFERED=1
    restart: unless-stopped
```

Start it:

```bash
docker compose up -d
docker compose logs -f
```

You should see:

```
Capture mode: local (sniffing auto-detected interface)
LocalSniffer starting on iface=None
* Running on http://0.0.0.0:8082
```

Open http://YOUR-HOST-IP:8082 in a browser.

## Step 3 — First-launch configuration

The dashboard launches with no credentials configured. Go straight to **Settings** (sidebar) and fill in:

| Section | Field | Value |
|---|---|---|
| Omada | Controller URL | `https://your-omada-controller` |
| Omada | Client ID | from step 1 |
| Omada | Client Secret | from step 1 |
| Fingerbank | API Key | from step 1 (or leave empty) |
| Gemini | API Key | from step 1 (or leave empty) |

Click **Test connection** under Omada to verify credentials, then **Save Settings**. Changes apply immediately — no restart needed.

Within ~30 seconds the Clients view should populate with every device Omada knows about, and the green status banner should read `Local sniffer live on local sniff on eth0 · N pkts (N frames, N DHCP, N mDNS)` with mDNS count climbing as devices announce themselves.

## Step 4 — Use it

- **Click any row** to see the full detail: DHCP fingerprint, vendor class, mDNS services, AI analysis
- **Click the ✨ icon** to run Gemini analysis on a single device
- **Click 🧠 Scan Unidentified** to AI-analyze every still-unknown device in one batch
- **Click 💬 Chat** to ask about your network in natural language — it queries your real event data to answer (see Step 5 for what it can do)
- **Click 🪄 Harmonize Names** to find inconsistently-named clusters (e.g. several iPhones with different naming conventions) and align them
- **Click Sync All Mismatched** to push proposed names back to Omada in bulk

The first run will be quiet — DHCP fingerprints take time to accumulate (one per device per lease renewal, typically every few hours to days). mDNS announcements arrive much faster, so Apple/Sonos/Hue/IoT devices will fingerprint within minutes.

## Step 5 — Syslog + network health AI (optional)

Feed your Omada controller's syslog to the dashboard to unlock event history and the Marvis-style network-health briefing.

### Enable syslog export on Omada

In the Omada controller UI, find the log/syslog export setting (the exact path varies by version — typically under Settings → Services, or Global/Site → Log Settings). Set:

- **Server IP:** the IP of the host running this dashboard
- **Server port:** `5514`
- **Protocol:** UDP

Save. The dashboard listens on UDP/5514 by default (a high port, so it needs no special privileges). With `network_mode: host` it's reachable on the host's IP automatically — no port mapping needed.

### Verify it's flowing

Open the **Syslog / Events** view in the sidebar. Within a minute the status banner should turn green: `Live on UDP/5514 from <controller-ip> · N received · N stored`. Events stream into the table below, colour-coded by severity, with known client MACs clickable to jump to their device row.

If the banner stays amber (`no events yet`), syslog isn't arriving — check the controller's export config and that nothing between it and the host blocks UDP/5514. You can confirm packets reach the host with `tcpdump -i any -n udp port 5514`. (After a container restart the banner reads `N stored · none since restart` if history exists but nothing new has arrived yet — that's normal.)

### Graphs and the time window

The Syslog view shows three live charts, all bounded to a time window you pick (15 min → 7 days) from the selector at the top:

- **Event activity** — a timeline of events per bucket, total vs. traffic-flow split
- **Top talkers** — busiest devices, resolved to their identified names; access points are badged `AP` and coloured differently so infrastructure stands out from clients
- **Event types** — the distribution across connect / disconnect / roam / auth / DHCP / flow / other

The window selector drives the AI briefing too, so you can scope analysis to "just the last 15 minutes" when chasing something live or "last 7 days" for a trend.

### Taming traffic-flow volume

Omada's firewall/flow logging is very high-volume and mostly noise for AIOps. The **Drop traffic-flow logs** toggle in the status banner discards those events at ingest (they're counted but not stored), so your event store and the briefing stay focused on meaningful lifecycle events, and the 100,000-row cap buys far more history. It persists across restarts and can also be set with `SYSLOG_DROP_TRAFFIC_FLOW=1`.

### Get a briefing

Click **✨ Analyze network** in the Syslog view. Gemini reviews the selected window of events alongside your device identifications and produces a briefing: an overall health verdict, the top issues worth attention (with the specific devices and likely root causes), security flags (e.g. distinguishing a stale saved password from a brute-force attempt), and a note on what's normal so routine churn doesn't alarm you. Device MACs in the briefing are clickable, and access points are labelled as infrastructure rather than mistaken for chatty clients.

### Ask the chatbot (Marvis-style)

The 💬 **Chat** button (on the Clients view toolbar) opens a conversational assistant that answers from your real event data. Instead of guessing, Gemini calls structured query tools — the modern equivalent of Juniper Marvis's `LIST` / `COUNT` / `STATUSOF` / `TROUBLESHOOT` / `ROAMINGOF` query language — and grounds its answer in what they return. The status line under each reply shows which tools it ran.

Things you can ask:

- *"How many times did my iPad disconnect today?"* — resolves the device, counts the real events, answers with the number
- *"Which devices are having connectivity issues?"* — ranks devices by problem events (auth failures, disconnects, deauths)
- *"Chart the top talkers this hour"* — one aggregation call, rendered as a bar chart
- *"Show event types as a breakdown"* — a doughnut of the distribution
- *"Troubleshoot the shed AP"* — full diagnostic for a device, by plain-language name
- *"Show roaming for my laptop over the last 7 days"* — AP-hop sequence and roam count over time (requires the controller to export client roaming events; if none are present, it says so rather than inventing them)

Each chat can be fleet-wide or scoped to a single device (expand a client row first). MACs in answers are clickable, and an analysis can be saved as the device's owner notes in one click.

### Network-health events via webhooks

Omada's syslog stream carries traffic flows and DHCP, but the real operational events — device disconnected, WAN down, rogue DHCP, IP/ARP conflicts, STP topology changes, loops, storms, attack detection — are delivered through the controller's **webhook/notification** channel, not syslog. Point those at the built-in receiver to fold them into the same event store.

In Omada: Logs → Notifications → enable **Webhook**, set Payload Template to **"Omada"** (not Google Chat), URL `http://YOUR-HOST:8082/api/webhook`, and enable the specific events you care about. To require a secret, set `WEBHOOK_TOKEN` in the environment — the app accepts it from Omada's `access_token` header, the `shardSecret` body field, or a `/api/webhook/<token>` URL path.

Webhook events classify into the same vocabulary as syslog (device_disconnected, wan_down, rogue_dhcp, etc.), so they show up in the graphs, feed the AI briefing, and are queryable by the chatbot. The status banner shows a 🔔 webhook counter, and clicking any event row reveals its full raw payload. Tip: the "Global Logs were sent automatically" notification is just log-forwarding chatter — disable that one in Omada to keep the feed focused on real events.

### A note on what's queryable

The chatbot and graphs reason over whatever your controller actually exports. Many Omada setups send firewall/flow logs heavily but little else — in that case you'll see lots of `traffic_flow` and `other`, and relatively few connect/roam/auth events. To get the richest AIOps experience, enable the controller's client and WLAN event logging (connect, disconnect, roaming, auth) in its syslog export settings. The `/api/aps` endpoint (`curl -s http://YOUR-HOST:8082/api/aps`) shows the AP MAC→name map the app uses to resolve infrastructure; an empty result there means the controller's device list wasn't reachable.

Storage is bounded: the newest 100,000 events are kept (configurable via `SYSLOG_MAX_ROWS`), oldest pruned beyond that. Set `SYSLOG_ENABLED=0` to turn ingestion off entirely.



### TZSP forwarding (when host networking isn't an option)

If you can't use `network_mode: host` (Docker Desktop on macOS/Windows, multi-VLAN setup where the dashboard host can't see the devices, etc.), configure your router to forward TZSP-encapsulated packets to the container instead. Requires a MikroTik or similar with a sniffer that supports TZSP streaming.

```yaml
services:
  sdn-identity-engine:
    image: farsonic/sdn-identity-engine:latest
    container_name: sdn-identity-engine
    ports:
      - "8082:8082"
      - "37008:37008/udp"             # TZSP receive port
    volumes:
      - ./instance:/app/instance
    environment:
      - CAPTURE_MODE=tzsp             # default, can also omit
      - DHCP_CAPTURE_PORT=37008
      - PYTHONUNBUFFERED=1
    restart: unless-stopped
```

On a MikroTik, configure the sniffer:

```
/tool sniffer set streaming-enabled=yes streaming-server=YOUR-DOCKER-HOST:37008 \
                  filter-port=bootps,bootpc,5353 filter-ip-protocol=udp \
                  filter-stream=yes
/tool sniffer start
```

(Substitute equivalent steps for other router platforms that support TZSP forwarding.)

## Troubleshooting

### "Local sniffer error: LocalSniffer crashed: Cannot set filter: libpcap is not available"

You're running an old version of the image. Pull the latest:
```
docker compose pull && docker compose up -d
```

### "Receiving frames but no mDNS yet" warning

Either:
- Your switch is doing IGMP snooping with link-local filtering enabled — try `tcpdump -i any -n udp port 5353` on the host to confirm whether mDNS is even reaching the NIC
- You're on a VLAN where mDNS doesn't flow — move the dashboard host to the device VLAN, or use a SPAN/mirror port

### "Test connection" fails with TLS error on Omada

Your controller has a self-signed cert. Either install the controller's CA into the container (advanced), or accept the verification skip — set `OMADA_VERIFY_TLS=0` in the environment (this is the default).

### "Test connection" returns 401 or 403

Check the Open API application's scope in Omada — it needs **Read** and **Write** permissions on **Site** resources. Some controller versions need you to explicitly grant access to specific sites.

### Devices show up but no DHCP fingerprints accumulate

DHCP renewals are infrequent — typically lease length / 2. If your lease is 24h, expect ~12h between fingerprint captures per device. Force a renewal on a test device (`sudo dhclient -r && sudo dhclient` on Linux, toggle Wi-Fi on a phone) to see if capture is working at all. mDNS announcements arrive much faster and should populate the 🪪 column within minutes.

### Container restarts in a loop

Check logs:
```
docker compose logs --tail=100 sdn-identity-engine
```

Most common cause: `cap_add: NET_RAW` missing or `network_mode: host` missing — the sniffer can't open raw sockets and crashes on startup.

## Upgrading

```bash
cd ~/sdn-identity-engine
docker compose pull
docker compose up -d
```

Your SQLite database in `./instance/` persists across upgrades, so all your saved credentials, device notes, AI analyses, and naming preferences carry forward.

## Privacy & data

- All data lives in your local `./instance/omada.db` SQLite file
- API keys you enter via the Settings UI are stored locally only, never sent anywhere except to the corresponding service when needed
- Gemini API calls send device metadata (DHCP fingerprint, mDNS service list, hostname, OUI, owner notes) to Google. Don't enter sensitive info in owner notes if this matters to you
- No telemetry, no phone-home, no analytics

## Changelog

### 0.2.2
- **Fixed "database is locked" errors under load** — SQLite now runs in WAL mode with a 30s busy-timeout and `synchronous=NORMAL`, so the background syslog writer and interactive dashboard reads no longer contend for an exclusive lock. The syslog commit path is also rollback-guarded so a transient lock can never kill the capture thread. (WAL creates `settings.db-wal`/`-shm` sidecar files in `instance/`; both are gitignored.)
- **Device identity in the event stream** — the events table CLIENT column now leads with the resolved device name (with the MAC underneath and a type note), not a bare MAC. Identity is batch-resolved in one query across the result set. Expanded event detail shows an Identity block (name, type, vendor, AP flag).
- **Bidirectional log ↔ client linking** — clicking an identified host in the log jumps to the Clients view and expands that device; the client detail pane gains a "Recent Log Events" section plus a "View in Syslog →" link that filters the event stream to that device.
- **Fixed TP-Link RFC5424 parsing** — the controller sends a space-separated `YYYY-MM-DD HH:MM:SS` timestamp (not a single ISO token), which shifted every field by one and mis-mapped the hostname to a time and the tag to the controller name. Now parsed correctly, with bare `-` treated as the RFC5424 nil value.
- **Webhook header auth** — `access_token` HTTP header (Omada's native method) now accepted alongside `shardSecret` body field and URL path token.

### 0.2.1
- **Webhook receiver** (`POST /api/webhook`, optional `/api/webhook/<token>`) — ingests Omada controller notifications (device disconnected, WAN down, rogue DHCP, IP/ARP conflict, STP changes, loops, storms, attacks, link/CPU/memory alerts) into the same event store, so they appear in graphs, the briefing, and the chatbot. Configure in Omada: Logs → Notifications → enable Webhook, payload template "Omada", URL `http://THIS-HOST:8082/api/webhook`.
- **Three-way webhook auth** — when `WEBHOOK_TOKEN` is set, the token is accepted from the `access_token` header (Omada's native method), the `shardSecret` body field, or the URL path.
- **Webhook counter** in the syslog status banner.
- **Expandable event rows** — click any event in the table to see all parsed fields plus the full raw payload (pretty-printed if JSON).
- Syslog parser now unpacks JSON-bodied controller events (e.g. `{"operation":"..."}`) into readable messages instead of storing raw JSON, and hardened against empty/control-only continuation fragments.

### 0.2.0
- **Marvis-style tool-using chatbot** — Gemini now answers from real event data via structured query tools (find device, count, list, rank, troubleshoot, roaming, aggregate) instead of guessing, and shows which tools it ran
- **Charts in chat** — ranked, distribution, and trend answers render as inline charts
- **Syslog graphs** — event-activity timeline, top talkers, and event-type breakdown, all time-windowed (15 min → 7 days), with the window also driving the AI briefing
- **Access-point name resolution** — AP MACs from flow logs resolve to their Omada names across graphs, briefing, and chat, and are clearly marked as infrastructure (new `/api/aps` diagnostic endpoint)
- **Roaming over time** — `ROAMINGOF`-style AP-hop history and roam counts for a device
- **Drop traffic-flow toggle** — discard high-volume firewall/flow logs at ingest to keep the event store focused on lifecycle events
- Fixed flow-log parsing to attribute events to the client (`MAC SRC`) rather than the AP, and a JSON-serialization crash on events with null fields

### 0.1.0
- Initial release: client identification (DHCP fingerprinting, mDNS, Fingerbank, Gemini), naming policy, syslog ingestion, and the on-demand network-health briefing

## License

Source: https://github.com/farsonic/sdn-identity-engine
Issues: https://github.com/farsonic/sdn-identity-engine/issues
