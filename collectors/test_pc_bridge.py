#!/usr/bin/env python3
import os
"""
test_pc_bridge.py

Tracks all traffic from the staging test PC — connected directly to
FortiGate port1, on its own subnet (192.168.30.0/24), NOT behind the
Cisco Meraki MX NAT that hides every other Norrsken device.

This means, uniquely for this project, source.ip filtering here
genuinely isolates ONE specific device's traffic — every other
dashboard in this project (SD-WAN SLA, RTC media, lane traffic, call
bitrate) reports network-wide aggregates blended across every
simultaneous user, because all real Norrsken member traffic is NATed
to a single Cisco MX IP before reaching the FortiGate. The test PC is
the first genuinely per-device view available in this whole pipeline.

Confirmed via _mapping/field lookup (2026-08-26): source.ip is mapped
as native ES `ip` type (not keyword), so a CIDR range query on
192.168.30.0/24 is valid and reliable.

Tracks three things, matching the pattern of the other bridges built
for this project:
  1. Latency/jitter (SD-WAN kernel SLA) — same numeric-field-only
     limitation as fortigate_sla_bridge.py: only latency and jitter
     are true stats aggregations; packetloss etc. are keyword-mapped
     and use latest-value only.
  2. Bandwidth — via sentdelta/rcvddelta (bytes in the polling window),
     NOT cumulative network.bytes, avoiding the overcounting bug found
     and fixed earlier in this project.
  3. Which shaping lane (L1-L4) the test PC's traffic is landing in —
     via fortinet.firewall.shapingpolicyname, same field used by
     lane_quality_bridge.py.

Poll interval: 120s, matching lookback window exactly (no overlap —
same fix applied to rtc_media_bridge.py earlier today after the
30s-poll/120s-lookback overlap issue was found).
"""

import time
import requests
from datetime import datetime

ES_URL   = "https://192.168.1.5:9200"
ES_USER  = "elastic"
ES_PASS  = os.environ["ES_PASSWORD"]
ES_INDEX = "logs-fortinet_fortigate.log-*"
VM_URL   = "http://localhost:8428/write"

POLL_INTERVAL = 120

TEST_PC_SUBNET = "192.168.30.0/24"

APPID_NAMES = {
    50535: "Unknown_50535", 16195: "HTTPS/DNS", 0: "Unknown",
    43541: "Microsoft.Teams", 47013: "SSL_TLSv1.3", 42533: "Google.Services",
    41469: "Microsoft.Portal", 15895: "SSL", 38924: "Microsoft.Azure",
    56688: "SSL_TLSv1.3_PQC", 38131: "Google.Accounts", 43345: "Slack",
    15817: "Gmail", 15893: "HTTPS_Browser", 39999: "WhatsApp_Web",
    48983: "Google.Meet", 41540: "SSL_TLSv1.2", 35766: "GitHub",
    37065: "Zoom", 32121: "Google.Drive",
    54418: "Microsoft.Teams_Audio", 54419: "Microsoft.Teams_Video",
    47385: "Zoom_Meeting", 40698: "WhatsApp_VoIP_Call",
    24426: "FaceTime", 43847: "Signal", 16350: "Webex",
}

MAX_PLAUSIBLE_LATENCY_MS = 5000


def query_sla():
    """Latency/jitter for test PC traffic specifically, per app."""
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{POLL_INTERVAL}s"}}},
                    {"term": {"fortinet.firewall.subtype": "sdwan"}},
                    {"range": {"fortinet.firewall.latency": {
                        "gt": 0, "lte": MAX_PLAUSIBLE_LATENCY_MS
                    }}}
                ],
                "filter": [
                    {"range": {"source.ip": {"gte": "192.168.30.0", "lte": "192.168.30.255"}}}
                ]
            }
        },
        "aggs": {
            "by_app": {
                "terms": {"field": "fortinet.firewall.appid", "size": 30},
                "aggs": {
                    "latency_stats": {"stats": {"field": "fortinet.firewall.latency"}},
                    "jitter_stats":  {"stats": {"field": "fortinet.firewall.jitter"}},
                    "sample_count":  {"value_count": {"field": "fortinet.firewall.latency"}}
                }
            }
        }
    }
    try:
        r = requests.post(f"{ES_URL}/{ES_INDEX}/_search", auth=(ES_USER, ES_PASS),
                           json=query, verify=False, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[{datetime.now()}] SLA query failed: {e}")
        return None


def query_bandwidth_and_lane():
    """Bandwidth (delta-based) and shaping lane for test PC traffic."""
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{POLL_INTERVAL}s"}}}
                ],
                "filter": [
                    {"range": {"source.ip": {"gte": "192.168.30.0", "lte": "192.168.30.255"}}}
                ]
            }
        },
        "aggs": {
            "by_lane": {
                "terms": {"field": "fortinet.firewall.shapingpolicyname", "size": 10, "missing": "unshaped"},
                "aggs": {
                    "sent_delta": {"sum": {"field": "fortinet.firewall.sentdelta"}},
                    "rcvd_delta": {"sum": {"field": "fortinet.firewall.rcvddelta"}},
                    "session_count": {"value_count": {"field": "network.bytes"}},
                    "by_app": {
                        "terms": {"field": "network.application", "size": 20}
                    }
                }
            }
        }
    }
    try:
        r = requests.post(f"{ES_URL}/{ES_INDEX}/_search", auth=(ES_USER, ES_PASS),
                           json=query, verify=False, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[{datetime.now()}] Bandwidth/lane query failed: {e}")
        return None


def push_to_vm(lines):
    if not lines:
        return
    try:
        r = requests.post(VM_URL, data="\n".join(lines), timeout=5)
        r.raise_for_status()
    except Exception as e:
        print(f"[{datetime.now()}] VM push failed: {e}")


def stat_or_none(stats_block, key):
    v = stats_block.get(key)
    return v if v is not None else None


def process_sla(data):
    lines = []
    if not data:
        return lines
    for app_bucket in data.get("aggregations", {}).get("by_app", {}).get("buckets", []):
        appid = app_bucket["key"]
        name = APPID_NAMES.get(appid, f"app_{appid}")
        safe_name = str(name).replace(" ", "_").replace(".", "_")
        n = app_bucket["sample_count"]["value"]
        if not n:
            continue
        lat = app_bucket["latency_stats"]
        jit = app_bucket["jitter_stats"]
        lat_avg = stat_or_none(lat, "avg")
        if lat_avg is None:
            continue
        tag = f"app={safe_name},appid={appid},site=norrsken-kigali"
        fields = [f"sample_count={int(n)}", f"latency={lat_avg}",
                  f"latency_max={stat_or_none(lat, 'max')}"]
        if stat_or_none(jit, "avg") is not None:
            fields.append(f"jitter={jit['avg']}")
            fields.append(f"jitter_max={jit['max']}")
        lines.append(f"testpc_sla,{tag} {','.join(fields)}")
        print(f"  [SLA] {name:25s} n={int(n)} latency={lat_avg:.1f}ms jitter={jit.get('avg')}")
    return lines


def process_bandwidth(data):
    lines = []
    if not data:
        return lines
    for lane_bucket in data.get("aggregations", {}).get("by_lane", {}).get("buckets", []):
        lane = str(lane_bucket["key"]).replace(" ", "_").replace("-", "_")
        sent = lane_bucket["sent_delta"]["value"] or 0
        rcvd = lane_bucket["rcvd_delta"]["value"] or 0
        sessions = lane_bucket["session_count"]["value"] or 0
        total = sent + rcvd

        top_apps = [b["key"] for b in lane_bucket.get("by_app", {}).get("buckets", [])[:3]]
        apps_str = "|".join(top_apps) if top_apps else "none"

        tag = f"lane={lane},site=norrsken-kigali,top_apps={apps_str}"
        fields = [
            f"total_bytes={total}", f"upload_bytes={sent}",
            f"download_bytes={rcvd}", f"session_count={sessions}"
        ]
        lines.append(f"testpc_lane_traffic,{tag} {','.join(fields)}")
        print(f"  [LANE] {lane:20s} sessions={sessions:.0f} bytes={total/1e6:.2f}MB top_apps={apps_str}")
    return lines


def main():
    print(f"[{datetime.now()}] test_pc_bridge starting")
    print(f"  Monitoring subnet: {TEST_PC_SUBNET} (isolated staging PC, NOT behind Meraki NAT)")
    print(f"  Poll interval: {POLL_INTERVAL}s (matches lookback exactly — no overlap)")
    while True:
        print(f"\n[{datetime.now()}] Polling...")
        sla_lines = process_sla(query_sla())
        bw_lines = process_bandwidth(query_bandwidth_and_lane())
        all_lines = sla_lines + bw_lines
        if all_lines:
            push_to_vm(all_lines)
            print(f"[{datetime.now()}] Pushed {len(all_lines)} records")
        else:
            print(f"[{datetime.now()}] No test PC traffic detected this window")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
