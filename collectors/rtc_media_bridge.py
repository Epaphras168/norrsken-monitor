#!/usr/bin/env python3
import os
"""
rtc_media_bridge.py

Tracks SD-WAN kernel SLA metrics (latency, jitter) specifically for
appids that FortiGuard classifies as genuine real-time media
(RTC-VOICE / RTC-VIDEO) — as opposed to signaling, chat, or file
transfer traffic from the same platforms.

Source: FortiGuard application signature reference table (provided
2026-08-25), cross-referencing which specific appid represents the
actual RTC media stream per platform:

  54418  Microsoft.Teams_Audio       RTC-VOICE
  54419  Microsoft.Teams_Video       RTC-VIDEO
  47385  Zoom_Meeting                RTC-VIDEO
  48983  Google.Meet                 RTC-VIDEO
  40698  WhatsApp_VoIP.Call          RTC-VIDEO
  24426  FaceTime                    RTC-VIDEO
  43847  Signal.Private.Messenger    RTC-VIDEO
  16350  Webex                       RTC-VIDEO

Deliberately excludes non-RTC appids from the same platforms (e.g.
Teams_Post 47822, Zoom_Meeting.Remote.Control 49830,
Zoom_Team.Chat 57226, WhatsApp_Web 39999, WhatsApp_File.Transfer 37371,
and Webex's chat/sharing/upload/download/login/whiteboard signatures),
since those are not real-time media traffic.

Uses `stats` aggregations for latency/jitter (confirmed numeric/float
fields in this ES mapping — see fortigate_sla_bridge.py for the same
finding). packetloss/replyjitter/originjitter/serverresponsetime are
keyword-mapped in this index and cannot use stats; latest-value
top_hits is used for those, same limitation as fortigate_sla_bridge.py.

POLL_INTERVAL and lookback window are set EQUAL (120s/120s), matching
the non-overlapping pattern used by fortigate_sla_bridge.py. An
earlier draft of this script used a 30s poll with a 120s lookback,
which caused the same underlying log entries to be re-aggregated into
multiple consecutive pushed values — correlated, overlapping windows
that would distort any downstream calculation spanning several stored
points (e.g. Grafana's "Mean" over a time range would over-weight
readings that happened to remain inside the window longest). Matching
poll interval to lookback window eliminates this: each push reflects
a distinct, non-overlapping 120-second slice, so every underlying
FortiGate log entry is counted exactly once across the stored series.
"""

import time
import requests
from datetime import datetime

ES_URL   = "https://192.168.1.5:9200"
ES_USER  = "elastic"
ES_PASS  = os.environ["ES_PASSWORD"]
ES_INDEX = "logs-fortinet_fortigate.log-*"
VM_URL   = "http://localhost:8428/write"

POLL_INTERVAL = 120  # poll and lookback are equal — no overlap, no double-counting

RTC_APPID_NAMES = {
    "54418": "Microsoft_Teams_Audio",
    "54419": "Microsoft_Teams_Video",
    "47385": "Zoom_Meeting",
    "48983": "Google_Meet",
    "40698": "WhatsApp_VoIP_Call",
    "24426": "FaceTime",
    "43847": "Signal_Private_Messenger",
    "16350": "Webex",
}

RTC_MEDIA_TYPE = {
    "54418": "voice",
    "54419": "video",
    "47385": "video",
    "48983": "video",
    "40698": "video",
    "24426": "video",
    "43847": "video",
    "16350": "video",
}

MAX_PLAUSIBLE_LATENCY_MS = 5000

KEYWORD_FIELDS = [
    "packetloss",
    "replyjitter",
    "originjitter",
    "serverresponsetime",
]


def query_es():
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{POLL_INTERVAL}s"}}},
                    {"term":  {"fortinet.firewall.subtype": "sdwan"}},
                    {"terms": {"fortinet.firewall.appid": list(RTC_APPID_NAMES.keys())}},
                    {"range": {"fortinet.firewall.latency": {
                        "gt": 0, "lte": MAX_PLAUSIBLE_LATENCY_MS
                    }}}
                ]
            }
        },
        "aggs": {
            "by_app": {
                "terms": {"field": "fortinet.firewall.appid", "size": len(RTC_APPID_NAMES)},
                "aggs": {
                    "by_interface": {
                        "terms": {"field": "fortinet.firewall.interface", "size": 10},
                        "aggs": {
                            "sample_count":  {"value_count": {"field": "fortinet.firewall.latency"}},
                            "latency_stats": {"stats": {"field": "fortinet.firewall.latency"}},
                            "jitter_stats":  {"stats": {"field": "fortinet.firewall.jitter"}},
                            "keyword_latest": {
                                "top_hits": {
                                    "size": 1,
                                    "sort": [{"@timestamp": {"order": "desc"}}],
                                    "_source": [f"fortinet.firewall.{f}" for f in KEYWORD_FIELDS]
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    try:
        r = requests.post(
            f"{ES_URL}/{ES_INDEX}/_search",
            auth=(ES_USER, ES_PASS),
            json=query,
            verify=False,
            timeout=10
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[{datetime.now()}] ES query failed: {e}")
        return None


def push_to_vm(lines):
    payload = "\n".join(lines)
    try:
        r = requests.post(VM_URL, data=payload, timeout=5)
        r.raise_for_status()
    except Exception as e:
        print(f"[{datetime.now()}] VM push failed: {e}")


def stat_or_none(stats_block, key):
    v = stats_block.get(key)
    return v if v is not None else None


def extract_keyword_fields(bucket):
    out = {f: None for f in KEYWORD_FIELDS}
    hits = bucket.get("keyword_latest", {}).get("hits", {}).get("hits", [])
    if not hits:
        return out
    fw = hits[0].get("_source", {}).get("fortinet", {}).get("firewall", {})
    for f in KEYWORD_FIELDS:
        raw = fw.get(f)
        if raw is None:
            continue
        try:
            out[f] = float(raw)
        except (TypeError, ValueError):
            out[f] = None
    return out


def process_results(data):
    if not data:
        return []

    lines = []
    app_buckets = data.get("aggregations", {}).get("by_app", {}).get("buckets", [])

    if not app_buckets:
        print(f"[{datetime.now()}] No RTC SD-WAN SLA data in window — no active calls")
        return []

    for app_bucket in app_buckets:
        appid = str(app_bucket["key"])
        app_name = RTC_APPID_NAMES.get(appid, f"app_{appid}")
        media_type = RTC_MEDIA_TYPE.get(appid, "unknown")
        safe_app = app_name.replace(" ", "_").replace(".", "_")

        for iface_bucket in app_bucket["by_interface"]["buckets"]:
            interface = iface_bucket["key"]
            n = iface_bucket["sample_count"]["value"]
            if not n:
                continue

            lat = iface_bucket["latency_stats"]
            jit = iface_bucket["jitter_stats"]

            lat_avg = stat_or_none(lat, "avg")
            if lat_avg is None:
                continue

            kw = extract_keyword_fields(iface_bucket)

            tag = (f"interface={interface},"
                   f"appid={appid},"
                   f"app={safe_app},"
                   f"media_type={media_type},"
                   f"site=norrsken-kigali")

            fields = [
                f"sample_count={int(n)}",
                f"latency={lat_avg}",
                f"latency_max={stat_or_none(lat, 'max')}",
            ]

            if stat_or_none(jit, "avg") is not None:
                fields.append(f"jitter={jit['avg']}")
                fields.append(f"jitter_max={jit['max']}")

            if kw["packetloss"] is not None:
                fields.append(f"packetloss={kw['packetloss']}")
            if kw["replyjitter"] is not None:
                fields.append(f"replyjitter={kw['replyjitter']}")
            if kw["originjitter"] is not None:
                fields.append(f"originjitter={kw['originjitter']}")
            if kw["serverresponsetime"] is not None:
                fields.append(f"server_response_time={kw['serverresponsetime']}")

            line = f"fortigate_rtc_sla,{tag} {','.join(fields)}"
            lines.append(line)

            print(f"  [{app_name:26s}] {media_type:5s} {interface}: "
                  f"n={int(n)} "
                  f"latency_avg={lat_avg:.1f}ms "
                  f"latency_max={stat_or_none(lat,'max')} "
                  f"jitter_avg={jit.get('avg')} "
                  f"packetloss(latest)={kw['packetloss']}")

    return lines


def main():
    print(f"[{datetime.now()}] rtc_media_bridge starting")
    print(f"  Tracking RTC-VOICE/RTC-VIDEO appids: {list(RTC_APPID_NAMES.values())}")
    print(f"  Poll interval: {POLL_INTERVAL}s (lookback window: {POLL_INTERVAL}s — no overlap)")
    while True:
        data = query_es()
        lines = process_results(data)
        if lines:
            push_to_vm(lines)
            print(f"[{datetime.now()}] Pushed {len(lines)} app+interface records")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
