#!/usr/bin/env python3
import os
"""
fortigate_sla_bridge.py

Uses Elasticsearch `stats` aggregations (avg, min, max) for latency and
jitter — the only two fields in this index confirmed to be mapped as
numeric (float). Every log entry within each 2-minute polling window
contributes to the avg/max for these two fields, not just the single
most recent one.

Confirmed via _mapping/field lookup that packetloss, replyjitter,
originjitter, and serverresponsetime are all mapped as `keyword`
(string) in this Elasticsearch index, not numeric — stats aggregations
are not supported on keyword fields. These four fields therefore use
top_hits (latest value in the window only), same behaviour as the
original script, while latency and jitter get the full avg/max
treatment.

A range filter (0 < latency <= 5000) is applied at the ES query level
so a single garbage/overflow reading can't corrupt the average before
it's even computed.

Field names are UNCHANGED from the previous script version so existing
Grafana panels keep working without edits. latency and jitter now
represent the AVERAGE over the window; the other four remain
latest-value snapshots as before. New _max fields are added for
latency and jitter. A new sample_count field shows how many real
latency/jitter measurements went into each stored point.
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

APPID_NAMES = {
    "15895":      "SSL",
    "4278190081": "Unknown",
    "35151":      "Apple.Maps",
    "42533":      "Google.Services",
    "47013":      "SSL_TLSv1.3",
    "55810":      "Claude",
    "38131":      "Google.Accounts",
    "15817":      "Gmail",
    "43541":      "Microsoft.Teams",
    "31077":      "YouTube",
    "43345":      "Slack",
    "35766":      "Github",
    "37065":      "Zoom",
    "48983":      "Google.Meet",
    "37197":      "Elastic",
    "32121":      "Google.Drive",
    "42662":      "Apple.Services",
    "29880":      "iCloud",
    "41540":      "SSL_TLSv1.2",
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
                    {"range": {"@timestamp": {"gte": "now-2m"}}},
                    {"term":  {"fortinet.firewall.subtype": "sdwan"}},
                    {"range": {"fortinet.firewall.latency": {
                        "gt": 0, "lte": MAX_PLAUSIBLE_LATENCY_MS
                    }}}
                ]
            }
        },
        "aggs": {
            "by_app": {
                "terms": {"field": "fortinet.firewall.appid", "size": 50},
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
        print(f"[{datetime.now()}] No SD-WAN SLA data in last 2 minutes")
        return []

    for app_bucket in app_buckets:
        appid = str(app_bucket["key"])
        app_name = APPID_NAMES.get(appid, f"app_{appid}")
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

            line = f"fortigate_sdwan_sla,{tag} {','.join(fields)}"
            lines.append(line)

            print(f"  [{app_name:20s}] {interface}: "
                  f"n={int(n)} "
                  f"latency_avg={lat_avg:.1f}ms "
                  f"latency_max={stat_or_none(lat,'max')} "
                  f"jitter_avg={jit.get('avg')} "
                  f"packetloss(latest)={kw['packetloss']}")

    return lines


def main():
    print(f"[{datetime.now()}] fortigate_sla_bridge starting "
          f"(avg/max for latency+jitter per {POLL_INTERVAL}s window; "
          f"packetloss/replyjitter/originjitter/serverresponsetime "
          f"remain latest-only — keyword-mapped fields, see docstring)")
    while True:
        data = query_es()
        lines = process_results(data)
        if lines:
            push_to_vm(lines)
            print(f"[{datetime.now()}] Pushed {len(lines)} app+interface records")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
