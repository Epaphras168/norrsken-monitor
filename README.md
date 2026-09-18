# EdgeIQ — Norrsken Network Monitoring

Network quality-of-experience (QoE) monitoring and a SpeedFusion/DSCP WAN-bonding
experiment for Norrsken House Kigali, delivered by Zuba Broadband. Monitors
real-time call quality (Zoom, Teams, Meet, WhatsApp, Webex) and bandwidth across
a multi-ISP setup (MTN, KOPA fiber + Starlink) to evaluate whether one fiber line
can be safely dropped in favor of Starlink as backup.

A SpeedFusion/DSCP routing change was applied 31 August 2026 but caused severe
packet loss and was reverted almost immediately. The project currently holds a
fully-validated ~24-day pre-intervention baseline (8–31 Aug); post-intervention
comparison is pending further testing.

---

## Getting started

### Prerequisites
- Access to the two machines this project spans (see Infrastructure below) —
  this repo's code runs *on* those machines, it isn't self-contained/portable
  to a laptop without them.
- Python 3.10+, `pip install elasticsearch psycopg2-binary requests`
- Docker + Docker Compose (for Grafana/Prometheus/Blackbox and, separately, the
  Postgres ETL target)

### Setup
1. Clone this repo onto the relevant machine (`elasticserver` for the
   collectors/monitoring stack, `datastorage` for the ETL/Postgres side).
2. Copy the credentials template and fill in real values — **never commit the
   filled-in `.env`, it's already git-ignored**:
   ```bash
   cp .env.example .env
   # edit .env with the real Elasticsearch and Grafana admin passwords
   ```
3. Bring up the monitoring stack (Elasticsearch/Grafana/Prometheus/Blackbox —
   `elasticserver` side):
   ```bash
   docker compose up -d
   docker ps   # confirm all services are healthy
   ```
4. For the ETL/Postgres side (`datastorage`), see `etl.py` and
   `docker-compose.yml` in that part of the repo — same `.env` pattern.
5. Every Python script and shell script in `collectors/`, `scripts/`, and
   `reports/` reads `ES_PASSWORD` from the environment — make sure it's
   exported in your shell (or sourced from `.env`) before running anything
   directly outside Docker:
   ```bash
   export $(cat .env | xargs)
   ```

---

## Repository structure

```
collectors/     # Bridge scripts: pull from Elasticsearch, push metrics to VictoriaMetrics
scripts/        # EDA / analysis scripts, archive.sh, disk_check.sh
scripts/data/   # One-off and recurring data-analysis scripts (bandwidth, field audits, etc.)
reports/        # generate_report.py — the client-facing report generator
grafana/        # Dashboard provisioning (datasources, dashboard JSON)
prometheus/     # Prometheus/VictoriaMetrics config
blackbox/       # Blackbox Exporter config (service reachability checks)
data/           # Runtime data output — git-ignored, regenerates from source
dscp_verification_procedure.md   # Manual verification steps for the DSCP/SpeedFusion test
```

---

## Architecture

```
FortiGate firewall (syslog)
        │
        ▼
Elasticsearch (elasticserver, port 9200)
   index: logs-fortinet_fortigate.log-*
        │
        ├──► collectors/*.py  ──► VictoriaMetrics ──► Grafana dashboards
        │
        └──► etl.py (on datastorage) ──► PostgreSQL (raw_* tables)
```

FortiGate splits data about one application across up to **three unrelated log
types**, joined only by `appid`:

| `type` | `subtype` | Has | Missing |
|---|---|---|---|
| `traffic` | `forward` | Real sessions, byte counts, app name (82%), lane tag | No quality metrics |
| `utm` | `app-ctrl` | `appid` ↔ app name mapping (**100% reliable**) | No session ID, no quality metrics |
| `event` | `sdwan` | Real `latency`/`jitter`/`packetloss` | **No sessionid, no source IP, no app name** — bare `appid` only |

No single document ever contains both an app name and a quality metric —
confirmed directly, this is a structural property of how FortiGate logs, not a
gap in our collection.

---

## Known data-quality issues — read before writing new queries

1. **32-bit overflow corruption.** `latency`/`originjitter` occasionally show
   physically impossible values (billions of ms). Ceiling filter: discard/null
   anything above 5000. `packetloss`/`replyjitter`/`serverresponsetime` are
   confirmed clean.
2. **`source.bytes`/`destination.bytes` are cumulative, not per-interval.**
   FortiGate re-logs a session's running total every ~2 min while it's open.
   Summing raw values overcounts massively. Use `sentdelta`/`rcvddelta`
   instead — confirmed correct per-interval deltas — but these are **only
   populated on the ~25% of sessions matching a shaping lane**.
3. **Day/chunk-boundary bug**: if you reset session-tracking state between
   processing chunks, a session spanning the boundary gets its entire
   multi-day total misattributed to one moment. Persist state across chunks.
4. **`fortigate_interface_rx_rate_bps`/`tx_rate_bps` in VictoriaMetrics are
   trustworthy** — real hardware counters, validated against Grafana. Prefer
   this over reconstructing bandwidth from session logs.
5. **VictoriaMetrics `query_range` staleness bug** on sparse/low-volume
   metrics — a single real reading can get silently repeated across many
   subsequent query windows. Cross-check low-volume metrics directly against
   Elasticsearch before trusting them.
6. **Meraki NAT blocks all per-device visibility.** Every member device sits
   behind shared NAT addresses — per-call, per-user troubleshooting is not
   possible from network logs alone with the current setup.
7. **Google Meet's real media stream is NOT under the obvious appid.**
   `Google.Meet` (`48983`) is 70% TCP (signaling/web). The real call stream is
   `37402` (`Google_Chat_Video_Call`), 87% UDP. Other platforms may have the
   same issue, unconfirmed — check `network.transport` split before trusting
   any platform's "quality" numbers.
8. **Postgres `execute_batch` silently splits into 100-row round trips**
   regardless of Python-side batch size — use `COPY` for bulk loads instead.
9. **Unsorted Elasticsearch `scan()` can poison a max-timestamp checkpoint** —
   never interrupt an unsorted-scan-based load mid-run; let it finish, since
   it still returns every document eventually, just not in order.

---

## What's built vs. still open

**Built:** ETL pipeline (Elasticsearch → Postgres, 3 of 9 log types populated,
checkpointed, duplicate-safe on `traffic_forward`), field audit + auto-generated
schema, bandwidth/quality analysis scripts, client-facing report generator,
three interim baseline reports + one full-baseline trend report.

**Not yet built:**
- `apps` dimension table (appid → name/category lookup) — schema exists,
  unpopulated
- Recurring ETL schedule (currently manual runs only)
- 6 of 9 raw tables unpopulated (`ssl`, `voip`, `system`, `security-rating`,
  `user`) — low priority per the field audit
- Hop/route (multi-ISP path) visibility — FortiGate has zero data on this
  (`vwlid` confirmed always `0` across 163M+ documents); would need new
  tooling, e.g. `syepes/network_exporter` (Prometheus-native MTR/traceroute,
  supports TCP-based tracing that follows real app paths) against each ISP
  uplink independently
- Per-call/per-device incident visibility — structurally blocked by Meraki
  NAT; realistic path is integrating each platform's own admin-side
  call-quality API and correlating by timestamp against network data

---

## Credentials

Never committed. Copy `.env.example` → `.env` and fill in real values locally
on each machine. Rotate any credential that was previously committed in this
repo's history before treating this as secure.
