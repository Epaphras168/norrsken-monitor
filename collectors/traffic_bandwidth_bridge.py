#!/usr/bin/env python3
import os
"""
Traffic Bandwidth Bridge
Queries Elasticsearch for FortiGate traffic log byte counts per application
and pushes aggregated bandwidth metrics to VictoriaMetrics.
Runs every 5 minutes.
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

POLL_INTERVAL = 120  # 5 minutes

# Real-time apps for traffic class tagging
REALTIME_APPS = {
    "Zoom",
    "Zoom_Meeting",
    "Microsoft.Teams",
    "Microsoft.Teams_Audio",
    "Microsoft.Teams_Video",
    "Google.Meet",
    "Google.Chat_Video.Call",
    "Slack",
    "WhatsApp_VoIP.Call",
    "Webex",
    "DTLS",
    "STUN",
}

def safe_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def query_bandwidth():
    """
    Aggregate bytes per application per egress interface
    over the last 5 minutes from traffic logs.
    """
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": "now-3m"}}},
                    {"exists": {"field": "network.application"}},
                    {"exists": {"field": "fortinet.firewall.sentdelta"}}
                ]
            }
        },
        "aggs": {
            "by_app": {
                "terms": {
                    "field": "network.application",
                    "size": 50
                },
                "aggs": {
                    "by_egress": {
                        "terms": {
                            "field": "observer.egress.interface.name",
                            "size": 10
                        },
                        "aggs": {
                            "total_bytes":   {"sum": {"script": {"source": "doc['fortinet.firewall.sentdelta'].value + doc['fortinet.firewall.rcvddelta'].value"}}},
                            "upload_bytes":  {"sum": {"field": "fortinet.firewall.sentdelta"}},
                            "download_bytes":{"sum": {"field": "fortinet.firewall.rcvddelta"}},
                            "session_count": {"value_count": {"field": "fortinet.firewall.sentdelta"}}
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
            timeout=15
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"[{datetime.now()}] ES query failed: {e}")
        return None


def process_and_push(data):
    if not data:
        return

    lines = []
    app_buckets = data.get("aggregations", {}).get("by_app", {}).get("buckets", [])

    if not app_buckets:
        print(f"[{datetime.now()}] No traffic data in last 5 minutes")
        return

    for app_bucket in app_buckets:
        app_name = app_bucket["key"].replace(".", "_").replace(" ", "_")
        traffic_class = "realtime" if app_bucket["key"] in REALTIME_APPS else "bulk"

        for iface_bucket in app_bucket["by_egress"]["buckets"]:
            interface     = iface_bucket["key"]
            total_bytes   = safe_float(iface_bucket["total_bytes"]["value"])
            upload_bytes  = safe_float(iface_bucket["upload_bytes"]["value"])
            download_bytes= safe_float(iface_bucket["download_bytes"]["value"])
            session_count = safe_float(iface_bucket["session_count"]["value"])

            if total_bytes is None:
                continue

            tag = (f"app={app_name},"
                   f"interface={interface},"
                   f"traffic_class={traffic_class},"
                   f"site=norrsken-kigali")

            fields = [
                f"total_bytes={total_bytes}",
                f"upload_bytes={upload_bytes or 0}",
                f"download_bytes={download_bytes or 0}",
                f"session_count={session_count or 0}"
            ]

            lines.append(f"fortigate_traffic,{tag} {','.join(fields)}")

            print(f"  [{app_name:25s}] {interface}: "
                  f"{total_bytes/1024:.1f}KB "
                  f"({session_count:.0f} sessions) "
                  f"[{traffic_class}]")

    if lines:
        payload = "\n".join(lines)
        try:
            r = requests.post(VM_URL, data=payload, timeout=5)
            r.raise_for_status()
            print(f"[{datetime.now()}] Pushed {len(lines)} bandwidth metrics to VM")
        except Exception as e:
            print(f"[{datetime.now()}] VM push failed: {e}")


def main():
    print(f"[{datetime.now()}] Traffic Bandwidth Bridge starting")
    print(f"  ES:  {ES_URL}")
    print(f"  VM:  {VM_URL}")
    print(f"  Poll interval: {POLL_INTERVAL}s")

    while True:
        print(f"\n[{datetime.now()}] Polling traffic logs...")
        data = query_bandwidth()
        process_and_push(data)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
