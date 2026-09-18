#!/usr/bin/env python3
import os
"""
Norrsken Weekly Network Performance Report Generator — v2
Fixes: ALL VictoriaMetrics queries now use the requested start/end period
(explicit timestamps via query_range) instead of silently defaulting to
"last N days from now". Previously only the Elasticsearch-backed functions
(app_latency_jitter, meet_kernel) respected the requested period; every
VictoriaMetrics-backed function ignored it and always returned live data.

Usage: python3 generate_report.py <start_iso> <end_iso> <report_date_label>
Example: python3 generate_report.py 2026-08-12T10:30:00Z 2026-08-15T15:04:00Z "17 August 2026"
"""

import sys
import json
import subprocess
import statistics
import requests
from datetime import datetime, timezone
from collections import defaultdict

requests.packages.urllib3.disable_warnings()

ES_URL = "https://192.168.1.5:9200"
ES_AUTH = ("elastic", os.environ["ES_PASSWORD"])
VM_QUERY_URL = "http://localhost:8428/api/v1/query"
VM_RANGE_URL = "http://localhost:8428/api/v1/query_range"

APPID_NAMES = {
    50535: "Unknown_50535", 16195: "HTTPS/DNS", 0: "Unknown",
    43541: "Microsoft.Teams", 47013: "SSL_TLSv1.3", 42533: "Google.Services",
    41469: "Microsoft.Portal", 15895: "SSL", 38924: "Microsoft.Azure",
    56688: "SSL_TLSv1.3_PQC", 38131: "Google.Accounts", 43345: "Slack",
    15817: "Gmail", 15893: "HTTPS_Browser", 39999: "WhatsApp_Web",
    48983: "Google.Meet", 41540: "SSL_TLSv1.2", 35766: "GitHub",
    37065: "Zoom", 32121: "Google.Drive", 37402: "Google_Meet_Video_Direct",
}


def iso_to_epoch(iso_str):
    return int(datetime.strptime(iso_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def es_query(body):
    r = requests.get(f"{ES_URL}/logs-fortinet_fortigate.log-*/_search",
                      auth=ES_AUTH, verify=False, json=body, timeout=30)
    r.raise_for_status()
    return r.json()


def vm_instant(query):
    r = requests.get(VM_QUERY_URL, params={"query": query}, timeout=15)
    r.raise_for_status()
    return r.json()


def vm_range(query, start_ts, end_ts, step="600s"):
    r = requests.get(VM_RANGE_URL, params={
        "query": query, "start": start_ts, "end": end_ts, "step": step
    }, timeout=30)
    r.raise_for_status()
    return r.json()


def vm_range_avg_per_series(query, start_ts, end_ts, step="600s"):
    data = vm_range(query, start_ts, end_ts, step)
    out = {}
    for r in data.get("data", {}).get("result", []):
        label = r["metric"].get("instance") or r["metric"].get("app") or \
                r["metric"].get("lane") or r["metric"].get("platform") or "unknown"
        vals = [float(v[1]) for v in r.get("values", []) if v[1] not in (None, "NaN")]
        if vals:
            out[label] = {
                "mean": statistics.mean(vals),
                "median": statistics.median(vals),
                "n": len(vals),
                "metric_full": r["metric"],
            }
    return out


def get_app_jitter_latency(start, end):
    body = {
        "size": 0,
        "query": {"bool": {"must": [
            {"range": {"@timestamp": {"gte": start, "lte": end}}},
            {"term": {"fortinet.firewall.subtype": "sdwan"}},
            {"range": {"fortinet.firewall.latency": {"lte": 5000}}}
        ]}},
        "aggs": {"by_app": {
            "terms": {"field": "fortinet.firewall.appid", "size": 20},
            "aggs": {
                "avg_latency": {"avg": {"field": "fortinet.firewall.latency"}},
                "max_latency": {"max": {"field": "fortinet.firewall.latency"}},
                "avg_jitter": {"avg": {"field": "fortinet.firewall.jitter"}},
                "max_jitter": {"max": {"field": "fortinet.firewall.jitter"}},
                "sample_count": {"value_count": {"field": "fortinet.firewall.latency"}}
            }
        }}
    }
    data = es_query(body)
    rows = []
    for b in data["aggregations"]["by_app"]["buckets"]:
        appid = b["key"]
        name = APPID_NAMES.get(appid, f"app_{appid}")
        rows.append({
            "app": name, "appid": appid,
            "avg_latency": round(b["avg_latency"]["value"], 1),
            "max_latency": round(b["max_latency"]["value"], 1),
            "avg_jitter": round(b["avg_jitter"]["value"], 1),
            "max_jitter": round(b["max_jitter"]["value"], 1),
            "count": b["sample_count"]["value"]
        })
    return sorted(rows, key=lambda r: -r["avg_jitter"])


def get_meet_kernel_quality(start, end):
    body = {
        "size": 0,
        "query": {"bool": {"must": [
            {"range": {"@timestamp": {"gte": start, "lte": end}}},
            {"term": {"fortinet.firewall.subtype": "sdwan"}},
            {"term": {"fortinet.firewall.appid": "37402"}},
            {"range": {"fortinet.firewall.latency": {"lte": 5000}}}
        ]}},
        "aggs": {
            "avg_latency": {"avg": {"field": "fortinet.firewall.latency"}},
            "max_latency": {"max": {"field": "fortinet.firewall.latency"}},
            "avg_jitter": {"avg": {"field": "fortinet.firewall.jitter"}},
            "max_jitter": {"max": {"field": "fortinet.firewall.jitter"}},
            "record_count": {"value_count": {"field": "fortinet.firewall.latency"}}
        }
    }
    data = es_query(body)["aggregations"]
    return {
        "records": data["record_count"]["value"],
        "avg_latency": round(data["avg_latency"]["value"], 1),
        "max_latency": round(data["max_latency"]["value"], 1),
        "avg_jitter": round(data["avg_jitter"]["value"], 1),
        "max_jitter": round(data["max_jitter"]["value"], 1),
    }


def get_service_availability(start_ts, end_ts):
    data = vm_range_avg_per_series('probe_success{site="norrsken-kigali"}', start_ts, end_ts)
    out = [{"instance": k, "pct": round(v["mean"] * 100, 2)} for k, v in data.items()]
    return sorted(out, key=lambda x: x["pct"])


def get_dns_latency(start_ts, end_ts):
    data = vm_range_avg_per_series('probe_duration_seconds{job="blackbox_icmp",site="norrsken-kigali"}', start_ts, end_ts)
    return [{"instance": k, "ms": round(v["mean"] * 1000, 1)} for k, v in data.items()]


def get_interface_throughput(start_ts, end_ts):
    rx = vm_range_avg_per_series('fortigate_interface_rx_rate_bps{interface="x3",site="norrsken-kigali"}', start_ts, end_ts)
    tx = vm_range_avg_per_series('fortigate_interface_tx_rate_bps{interface="x3",site="norrsken-kigali"}', start_ts, end_ts)
    rx_v = next(iter(rx.values()), None)
    tx_v = next(iter(tx.values()), None)
    return {
        "rx_mean_mbps": round(rx_v["mean"] / 1e6, 1) if rx_v else None,
        "rx_median_mbps": round(rx_v["median"] / 1e6, 1) if rx_v else None,
        "tx_mean_mbps": round(tx_v["mean"] / 1e6, 1) if tx_v else None,
        "tx_median_mbps": round(tx_v["median"] / 1e6, 1) if tx_v else None,
        "rx_samples": rx_v["n"] if rx_v else 0,
        "tx_samples": tx_v["n"] if tx_v else 0,
    }


def get_traffic_split(start_ts, end_ts):
    rt = vm_range_avg_per_series('sum(fortigate_traffic_total_bytes{site="norrsken-kigali",traffic_class="realtime"})', start_ts, end_ts)
    bk = vm_range_avg_per_series('sum(fortigate_traffic_total_bytes{site="norrsken-kigali",traffic_class="bulk"})', start_ts, end_ts)
    rt_v = next(iter(rt.values()), {"mean": 0})["mean"]
    bk_v = next(iter(bk.values()), {"mean": 0})["mean"]
    total = rt_v + bk_v
    return {
        "rt_mb": round(rt_v / 1e6, 1), "bk_mb": round(bk_v / 1e6, 1),
        "rt_pct": round((rt_v / total) * 100, 1) if total else 0,
        "bk_pct": round((bk_v / total) * 100, 1) if total else 0,
    }


def get_call_bitrate(start_ts, end_ts):
    data = vm_range('real_time_media_quality_instant_total_bps{site="norrsken-kigali"}', start_ts, end_ts)
    platform_vals = defaultdict(list)
    for r in data.get("data", {}).get("result", []):
        p = r["metric"].get("platform", "unknown")
        if p in ("Google_Meet", "Google_Meet_Video"):
            p = "Google_Meet"
        vals = [float(v[1]) for v in r.get("values", []) if v[1] not in (None, "NaN") and float(v[1]) > 0]
        platform_vals[p].extend(vals)
    out = {}
    for p, vals in platform_vals.items():
        if vals:
            out[p] = {
                "avg_mbps": round(sum(vals) / len(vals) / 1e6, 2),
                "peak_mbps": round(max(vals) / 1e6, 2),
                "n": len(vals)
            }
    return out


def get_lane_traffic(start_ts, end_ts):
    sessions = vm_range_avg_per_series('fortigate_lane_traffic_session_count{site="norrsken-kigali"}', start_ts, end_ts)
    mb = vm_range_avg_per_series('fortigate_lane_traffic_total_bytes{site="norrsken-kigali"}', start_ts, end_ts)
    out = {}
    for lane, v in sessions.items():
        out.setdefault(lane, {})["avg_sessions_per_window"] = round(v["mean"], 1)
    for lane, v in mb.items():
        out.setdefault(lane, {})["avg_mb_per_window"] = round(v["mean"] / 1e6, 1)
    return out


def get_lane_quality(start_ts, end_ts):
    lane_apps = {
        "L1_RealTime":      ["Zoom", "Microsoft.Teams", "Google.Meet"],
        "L2_HandOnControl": ["Github"],
        "L3_Everyday":      ["Slack", "Gmail"],
        "L4_Background":    ["Google.Drive"],
    }
    out = {}
    for lane, apps in lane_apps.items():
        regex = "|".join(a.replace(".", "_") for a in apps)
        lat = vm_range_avg_per_series(f'avg(fortigate_sdwan_sla_latency{{site="norrsken-kigali",app=~"{regex}"}})', start_ts, end_ts)
        jit = vm_range_avg_per_series(f'avg(fortigate_sdwan_sla_jitter{{site="norrsken-kigali",app=~"{regex}"}})', start_ts, end_ts)
        lat_v = next(iter(lat.values()), None)
        jit_v = next(iter(jit.values()), None)
        out[lane] = {
            "avg_latency_ms": round(lat_v["mean"], 1) if lat_v else None,
            "avg_jitter_ms": round(jit_v["mean"], 1) if jit_v else None,
            "representative_apps": apps
        }
    return out


def main():
    if len(sys.argv) != 4:
        print("Usage: generate_report.py <start_iso> <end_iso> <report_date_label>")
        print('Example: generate_report.py 2026-08-12T10:30:00Z 2026-08-15T15:04:00Z "17 August 2026"')
        sys.exit(1)

    start, end, report_date = sys.argv[1], sys.argv[2], sys.argv[3]
    start_ts = iso_to_epoch(start)
    end_ts = iso_to_epoch(end)

    print(f"Pulling data for {start} to {end} (epoch {start_ts}-{end_ts})...")
    result = {
        "period_start": start,
        "period_end": end,
        "report_date": report_date,
        "app_latency_jitter": get_app_jitter_latency(start, end),
        "meet_kernel": get_meet_kernel_quality(start, end),
        "service_availability": get_service_availability(start_ts, end_ts),
        "dns_latency": get_dns_latency(start_ts, end_ts),
        "interface": get_interface_throughput(start_ts, end_ts),
        "traffic_split": get_traffic_split(start_ts, end_ts),
        "call_bitrate": get_call_bitrate(start_ts, end_ts),
        "lane_traffic": get_lane_traffic(start_ts, end_ts),
        "lane_quality": get_lane_quality(start_ts, end_ts),
    }

    outfile = f"/opt/norrsken-monitor/reports/report_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    subprocess.run(["mkdir", "-p", "/opt/norrsken-monitor/reports"])
    with open(outfile, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Data pulled successfully. Saved to {outfile}")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
