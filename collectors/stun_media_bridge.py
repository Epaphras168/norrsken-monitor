#!/usr/bin/env python3
import os
"""
Real-Time Media Quality Bridge
Tracks actual video/audio call quality from FortiGate traffic logs.

Two measurement paths:
1. STUN large flows — Teams (ASN 8075), Google Meet (ASN 15169)
2. Direct app classification — Zoom_Meeting, WhatsApp_VoIP.Call, Microsoft.Teams, Google.Chat_Video.Call

Two bitrate calculations:
- Instantaneous: from sentdelta/rcvddelta (2-min window) — real-time quality
- Cumulative: from total session bytes — overall call quality

Poll interval: 120 seconds (matches FortiGate 2-minute session update interval)
"""

import time
import requests
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

ES_URL   = "https://192.168.1.5:9200"
ES_USER  = "elastic"
ES_PASS  = os.environ["ES_PASSWORD"]
ES_INDEX = "logs-fortinet_fortigate.log-*"
VM_URL   = "http://localhost:8428/write"

POLL_INTERVAL      = 120
QUERY_WINDOW       = "now-3m"
MIN_MEDIA_BYTES    = 500000

PLATFORM_ASN = {
    8075:  "Microsoft_Teams",
    15169: "Google_Meet",
    13445: "Webex",
}

APP_PLATFORM_MAP = {
    "Google.Chat_Video.Call": "Google_Meet_Video",
    "WhatsApp_VoIP.Call":     "WhatsApp_Voice",
    "Zoom_Meeting":           "Zoom",
    "Microsoft.Teams":        "Microsoft_Teams",
    "Microsoft.Teams_Audio":  "Microsoft_Teams",
    "Microsoft.Teams_Video":  "Microsoft_Teams",
}

DELTA_DURATION_SEC = 120


def safe_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def query_stun_media():
    """Query large STUN UDP flows by destination ASN."""
    return requests.post(
        f"{ES_URL}/{ES_INDEX}/_search",
        auth=(ES_USER, ES_PASS),
        json={
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": QUERY_WINDOW}}},
                        {"term": {"network.application": "STUN"}},
                        {"term": {"network.transport": "udp"}},
                        {"range": {"network.bytes": {"gte": MIN_MEDIA_BYTES}}}
                    ]
                }
            },
            "aggs": {
                "by_asn": {
                    "terms": {"field": "destination.as.number", "size": 20},
                    "aggs": {
                        "total_bytes":    {"sum": {"field": "network.bytes"}},
                        "total_upload":   {"sum": {"field": "source.bytes"}},
                        "total_download": {"sum": {"field": "destination.bytes"}},
                        "total_dur_ns":   {"sum": {"field": "event.duration"}},
                        "sum_sentdelta":  {"sum": {"field": "fortinet.firewall.sentdelta"}},
                        "sum_rcvddelta":  {"sum": {"field": "fortinet.firewall.rcvddelta"}},
                        "session_count":  {"value_count": {"field": "network.bytes"}},
                        "relay_geo": {
                            "top_hits": {
                                "size": 1,
                                "sort": [{"@timestamp": {"order": "desc"}}],
                                "_source": [
                                    "destination.geo.city_name",
                                    "destination.geo.country_name"
                                ]
                            }
                        }
                    }
                }
            }
        },
        verify=False, timeout=15
    ).json()


def query_direct_media():
    """Query directly classified media apps."""
    return requests.post(
        f"{ES_URL}/{ES_INDEX}/_search",
        auth=(ES_USER, ES_PASS),
        json={
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": QUERY_WINDOW}}},
                        {"terms": {"network.application": list(APP_PLATFORM_MAP.keys())}},
                        {"range": {"network.bytes": {"gte": MIN_MEDIA_BYTES}}}
                    ]
                }
            },
            "aggs": {
                "by_app": {
                    "terms": {"field": "network.application", "size": 10},
                    "aggs": {
                        "total_bytes":    {"sum": {"field": "network.bytes"}},
                        "total_upload":   {"sum": {"field": "source.bytes"}},
                        "total_download": {"sum": {"field": "destination.bytes"}},
                        "total_dur_ns":   {"sum": {"field": "event.duration"}},
                        "sum_sentdelta":  {"sum": {"field": "fortinet.firewall.sentdelta"}},
                        "sum_rcvddelta":  {"sum": {"field": "fortinet.firewall.rcvddelta"}},
                        "session_count":  {"value_count": {"field": "network.bytes"}},
                        "relay_geo": {
                            "top_hits": {
                                "size": 1,
                                "sort": [{"@timestamp": {"order": "desc"}}],
                                "_source": [
                                    "destination.geo.city_name",
                                    "destination.geo.country_name",
                                    "destination.as.organization.name"
                                ]
                            }
                        }
                    }
                }
            }
        },
        verify=False, timeout=15
    ).json()


def build_line(platform, relay_city, relay_country,
               total_bytes, total_upload, total_download,
               total_dur_ns, session_count,
               sentdelta, rcvddelta):

    city    = (relay_city or "unknown").replace(" ", "_")
    country = (relay_country or "unknown").replace(" ", "_")

    if total_dur_ns and total_dur_ns > 0:
        dur_sec        = total_dur_ns / 1_000_000_000
        cumulative_bps = (total_bytes * 8) / dur_sec
    else:
        dur_sec = cumulative_bps = 0

    instant_upload_bps   = (sentdelta * 8) / DELTA_DURATION_SEC if sentdelta else 0
    instant_download_bps = (rcvddelta * 8) / DELTA_DURATION_SEC if rcvddelta else 0
    instant_total_bps    = instant_upload_bps + instant_download_bps

    upload_ratio = (total_upload / total_bytes) if total_bytes > 0 else 0

    upload_kbps = instant_upload_bps / 1000
    if upload_kbps < 50:
        call_type = "audio_only"
    elif upload_kbps < 500:
        call_type = "video_low"
    elif upload_kbps < 1500:
        call_type = "video_medium"
    else:
        call_type = "video_hd"

    tag = (f"platform={platform},"
           f"call_type={call_type},"
           f"relay_city={city},"
           f"relay_country={country},"
           f"site=norrsken-kigali")

    fields = [
        f"total_bytes={total_bytes:.0f}",
        f"upload_bytes={total_upload:.0f}",
        f"download_bytes={total_download:.0f}",
        f"cumulative_bitrate_bps={cumulative_bps:.0f}",
        f"instant_upload_bps={instant_upload_bps:.0f}",
        f"instant_download_bps={instant_download_bps:.0f}",
        f"instant_total_bps={instant_total_bps:.0f}",
        f"upload_ratio={upload_ratio:.3f}",
        f"session_count={session_count:.0f}",
        f"duration_sec={dur_sec:.0f}"
    ]

    print(f"  [{platform:25s}] {city},{country}")
    print(f"    Sessions:{session_count:.0f} "
          f"CumBitrate:{cumulative_bps/1e6:.2f}Mbps "
          f"InstBitrate:{instant_total_bps/1e6:.2f}Mbps "
          f"Upload%:{upload_ratio*100:.0f}%")

    return f"real_time_media_quality,{tag} {','.join(fields)}"


def process_stun(data):
    lines = []
    for b in data.get("aggregations", {}).get("by_asn", {}).get("buckets", []):
        asn      = b["key"]
        platform = PLATFORM_ASN.get(asn)
        if not platform:
            continue

        hits = b.get("relay_geo", {}).get("hits", {}).get("hits", [])
        geo  = hits[0]["_source"].get("destination", {}).get("geo", {}) if hits else {}

        lines.append(build_line(
            platform       = platform,
            relay_city     = geo.get("city_name"),
            relay_country  = geo.get("country_name"),
            total_bytes    = safe_float(b["total_bytes"]["value"]),
            total_upload   = safe_float(b["total_upload"]["value"]),
            total_download = safe_float(b["total_download"]["value"]),
            total_dur_ns   = safe_float(b["total_dur_ns"]["value"]),
            session_count  = safe_float(b["session_count"]["value"]),
            sentdelta      = safe_float(b["sum_sentdelta"]["value"]),
            rcvddelta      = safe_float(b["sum_rcvddelta"]["value"])
        ))
    return lines


def process_direct(data):
    lines = []
    seen_platforms = set()

    for b in data.get("aggregations", {}).get("by_app", {}).get("buckets", []):
        app_name = b["key"]
        platform = APP_PLATFORM_MAP.get(app_name, app_name.replace(".", "_"))

        hits = b.get("relay_geo", {}).get("hits", {}).get("hits", [])
        geo  = hits[0]["_source"].get("destination", {}).get("geo", {}) if hits else {}

        # If platform already seen (e.g. Microsoft_Teams from both Teams and Teams_Audio)
        # we still push separate lines — VictoriaMetrics will sum them
        lines.append(build_line(
            platform       = platform,
            relay_city     = geo.get("city_name"),
            relay_country  = geo.get("country_name"),
            total_bytes    = safe_float(b["total_bytes"]["value"]),
            total_upload   = safe_float(b["total_upload"]["value"]),
            total_download = safe_float(b["total_download"]["value"]),
            total_dur_ns   = safe_float(b["total_dur_ns"]["value"]),
            session_count  = safe_float(b["session_count"]["value"]),
            sentdelta      = safe_float(b["sum_sentdelta"]["value"]),
            rcvddelta      = safe_float(b["sum_rcvddelta"]["value"])
        ))
        seen_platforms.add(platform)
    return lines


def main():
    print(f"[{datetime.now()}] Real-Time Media Quality Bridge starting")
    print(f"  STUN ASN path: Teams (8075), Google Meet (15169), Webex (13445)")
    print(f"  Direct app path: {list(APP_PLATFORM_MAP.keys())}")
    print(f"  Poll: {POLL_INTERVAL}s | Window: {QUERY_WINDOW}")

    while True:
        print(f"\n[{datetime.now()}] Polling...")
        lines = []

        try:
            stun_data = query_stun_media()
            lines += process_stun(stun_data)
        except Exception as e:
            print(f"  STUN query error: {e}")

        try:
            direct_data = query_direct_media()
            lines += process_direct(direct_data)
        except Exception as e:
            print(f"  Direct query error: {e}")

        if lines:
            try:
                r = requests.post(VM_URL, data="\n".join(lines), timeout=5)
                r.raise_for_status()
                print(f"  Pushed {len(lines)} media quality metrics to VM")
            except Exception as e:
                print(f"  VM push failed: {e}")
        else:
            print("  No active calls detected")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
