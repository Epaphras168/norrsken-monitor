#!/usr/bin/env python3
import os
"""
One-time backfill script.
Queries all historical FortiGate SD-WAN SLA records from Elasticsearch
and pushes them to VictoriaMetrics with correct timestamps.
Run once — safe to re-run (VM deduplicates by timestamp).
"""

import time
import requests
from datetime import datetime, timezone
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

ES_URL   = "https://192.168.1.5:9200"
ES_USER  = "elastic"
ES_PASS  = os.environ["ES_PASSWORD"]
ES_INDEX = "logs-fortinet_fortigate.log-*"
VM_URL   = "http://localhost:8428/write"


APPID_NAMES = {
    "15895": "SSL", "4278190081": "Unknown", "35151": "Apple_Maps",
    "42533": "Google_Services", "47013": "SSL_TLSv1_3", "55810": "Claude",
    "38131": "Google_Accounts", "15817": "Gmail", "43541": "Microsoft_Teams",
    "31077": "YouTube", "43345": "Slack", "35766": "Github",
    "37065": "Zoom", "48983": "Google_Meet", "37197": "Elastic",
    "32121": "Google_Drive", "42662": "Apple_Services", "29880": "iCloud",
    "41540": "SSL_TLSv1_2",
}

START_DATE = "2026-07-24T00:00:00Z"
BATCH_SIZE = 500
VM_BATCH   = 200


def safe_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def fetch_batch(search_after=None):
    query = {
        "size": BATCH_SIZE,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": START_DATE}}},
                    {"exists": {"field": "fortinet.firewall.latency"}},
                    {"term":  {"fortinet.firewall.subtype": "sdwan"}}
                ]
            }
        },
        "sort": [
            {"@timestamp": {"order": "asc"}},
            {"_seq_no":    {"order": "asc"}}
        ],
        "_source": [
            "@timestamp",
            "fortinet.firewall.latency",
            "fortinet.firewall.jitter",
            "fortinet.firewall.packetloss",
            "fortinet.firewall.replyjitter",
            "fortinet.firewall.originjitter",
            "fortinet.firewall.serverresponsetime",
                "fortinet.firewall.appid",
            "fortinet.firewall.interface"
        ]
    }

    if search_after:
        query["search_after"] = search_after

    r = requests.post(
        f"{ES_URL}/{ES_INDEX}/_search",
        auth=(ES_USER, ES_PASS),
        json=query,
        verify=False,
        timeout=30
    )
    r.raise_for_status()
    return r.json()


def build_line(doc):
    src = doc["_source"]
    fw  = src.get("fortinet", {}).get("firewall", {})

    interface = fw.get("interface", "unknown")
    latency   = safe_float(fw.get("latency"))

    if latency is None:
        return None

    ts_str = src.get("@timestamp", "")
    try:
        ts_str_clean = ts_str.replace("+00:00", "Z")
        if ts_str_clean.endswith("Z"):
            dt = datetime.fromisoformat(ts_str_clean.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(ts_str_clean)
        ts_ns = int(dt.timestamp() * 1_000_000_000)
    except Exception:
        return None

    appid_str = str(int(float(fw.get("appid", 0))))
    app_name  = APPID_NAMES.get(appid_str, f"app_{appid_str}").replace(".", "_")
    tag    = f"interface={interface},appid={appid_str},app={app_name},site=norrsken-kigali"
    fields = [f"latency={latency}"]

    jitter      = safe_float(fw.get("jitter"))
    packetloss  = safe_float(fw.get("packetloss"))
    replyjitter = safe_float(fw.get("replyjitter"))
    originjitter= safe_float(fw.get("originjitter"))
    srt         = safe_float(fw.get("serverresponsetime"))

    if jitter       is not None: fields.append(f"jitter={jitter}")
    if packetloss   is not None: fields.append(f"packetloss={packetloss}")
    if replyjitter  is not None: fields.append(f"replyjitter={replyjitter}")
    if originjitter is not None: fields.append(f"originjitter={originjitter}")
    if srt          is not None: fields.append(f"server_response_time={srt}")

    return f"fortigate_sdwan_sla,{tag} {','.join(fields)} {ts_ns}"


def push_batch(lines):
    payload = "\n".join(lines)
    r = requests.post(VM_URL, data=payload, timeout=10)
    r.raise_for_status()


def main():
    print(f"Starting backfill from {START_DATE}")
    print(f"ES: {ES_URL}")
    print(f"VM: {VM_URL}")
    print()

    total_fetched = 0
    total_pushed  = 0
    search_after  = None
    vm_buffer     = []
    batch_num     = 0

    while True:
        data = fetch_batch(search_after)
        hits = data.get("hits", {}).get("hits", [])

        if not hits:
            print(f"\nDone. Fetched {total_fetched} records, pushed {total_pushed} metrics.")
            break

        batch_num += 1
        print(f"Batch {batch_num}: {len(hits)} records", end="", flush=True)

        for doc in hits:
            line = build_line(doc)
            if line:
                vm_buffer.append(line)
                total_pushed += 1

            if len(vm_buffer) >= VM_BATCH:
                push_batch(vm_buffer)
                vm_buffer = []
                print(".", end="", flush=True)

        total_fetched += len(hits)
        # Use sort values as cursor for next page
        search_after = hits[-1]["sort"]

        time.sleep(0.2)

    if vm_buffer:
        push_batch(vm_buffer)
        print(f"\nFlushed final {len(vm_buffer)} metrics.")

    print(f"\nBackfill complete.")
    print(f"  Total ES records fetched: {total_fetched}")
    print(f"  Total VM metrics pushed:  {total_pushed}")
    print(f"\nIn Grafana, set time range to 'Last 10 days' to see full history.")


if __name__ == "__main__":
    main()
