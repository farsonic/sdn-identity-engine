# SDN Identity Engine

A self-hosted dashboard for identifying, naming, and managing every client on your TP-Link Omada-managed network. Combines DHCP fingerprinting, mDNS/Bonjour observation, Fingerbank lookups, and Gemini AI analysis to turn rows of "android-1234" and unknown MAC addresses into meaningful device names, automatically.

![dashboard](https://raw.githubusercontent.com/farsonic/sdn-identity-engine/main/docs/screenshot.png)

## What you get

- **All clients in one table** — name, MAC, IP, OS, vendor, AP/switch, DHCP fingerprint, mDNS services
- **Auto-identification** — DHCP fingerprints captured passively, looked up against Fingerbank, optionally analyzed by Gemini for a full device dossier
- **Naming policy** — define a template (e.g. `{type}-{vendor}-{lastoctet}`), apply across the fleet, push back to Omada
- **AI chat** — ask Gemini about your network ("which devices haven't been identified?") or any single device, save the analysis as device notes in one click
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
- **Click 💬 Chat** to ask Gemini about your network in natural language
- **Click 🪄 Harmonize Names** to find inconsistently-named clusters (e.g. several iPhones with different naming conventions) and align them
- **Click Sync All Mismatched** to push proposed names back to Omada in bulk

The first run will be quiet — DHCP fingerprints take time to accumulate (one per device per lease renewal, typically every few hours to days). mDNS announcements arrive much faster, so Apple/Sonos/Hue/IoT devices will fingerprint within minutes.

## Alternative capture modes

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

## License

Source: https://github.com/farsonic/sdn-identity-engine
Issues: https://github.com/farsonic/sdn-identity-engine/issues
