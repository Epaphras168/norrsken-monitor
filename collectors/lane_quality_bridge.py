#!/usr/bin/env python3
import os
"""
Traffic Lane Quality Bridge
Tracks quantity (sessions/bytes) per traffic shaping lane (L1-L4) as
configured on FortiGate shaping-policy.

Uses sentdelta/rcvddelta (bytes transferred in the last poll window)
instead of cumulative network.bytes, to avoid overcounting long-lived
sessions (same fix applied earlier to traffic_bandwidth_bridge.py).

Poll interval: 120 seconds
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

POLL_INTERVAL = 120


def query_lane_traffic():
    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-2m"}}},
                    {"exists": {"field": "fortinet.firewall.shapingpolicyname"}}
                ]
            }
        },
        "aggs": {
            "by_lane": {
                "terms": {"field": "fortinet.firewall.shapingpolicyname", "size": 10},
                "aggs": {
                    "sent_delta":    {"sum": {"field": "fortinet.firewall.sentdelta"}},
                    "rcvd_delta":    {"sum": {"field": "fortinet.firewall.rcvddelta"}},
                    "session_count": {"value_count": {"field": "network.bytes"}}
                }
            }
        }
    }
    r = requests.post(f"{ES_URL}/{ES_INDEX}/_search", auth=(ES_USER, ES_PASS),
                       json=body, verify=False, timeout=15)
    r.raise_for_status()
    return r.json()


def process_traffic(data):
    lines = []
    buckets = data.get("aggregations", {}).get("by_lane", {}).get("buckets", [])
    for b in buckets:
        lane = b["key"].replace(" ", "_").replace("-", "_")
        sent_delta     = b["sent_delta"]["value"] or 0
        rcvd_delta     = b["rcvd_delta"]["value"] or 0
        total_bytes    = sent_delta + rcvd_delta
        session_count  = b["session_count"]["value"] or 0

        tag = f"lane={lane},site=norrsken-kigali"
        fields = [
            f"total_bytes={total_bytes}",
            f"upload_bytes={sent_delta}",
            f"download_bytes={rcvd_delta}",
            f"session_count={session_count}"
        ]
        lines.append(f"fortigate_lane_traffic,{tag} {','.join(fields)}")
        print(f"  [{lane:25s}] {session_count:.0f} sessions, "
              f"{total_bytes/1e6:.1f}MB (delta-based)")
    return lines


def push(lines):
    if not lines:
        return
    try:
        r = requests.post(VM_URL, data="\n".join(lines), timeout=5)
        r.raise_for_status()
        print(f"  Pushed {len(lines)} lane metrics to VM")
    except Exception as e:
        print(f"  VM push failed: {e}")


def main():
    print(f"[{datetime.now()}] Lane Quality Bridge starting (delta-based)")
    print(f"  Tracking lanes: L1, L2, L3, L4")
    print(f"  Poll interval: {POLL_INTERVAL}s")

    while True:
        print(f"\n[{datetime.now()}] Polling lane traffic...")
        try:
            data = query_lane_traffic()
            lines = process_traffic(data)
            push(lines)
        except Exception as e:
            print(f"  Error: {e}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
