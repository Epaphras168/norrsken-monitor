#!/usr/bin/env python3
import time
import requests
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

FGT_HOST  = "https://192.168.1.1"
FGT_TOKEN = "kGb6xkNkbych1r4Nwndhtg0kG0974q"
VM_URL    = "http://localhost:8428/write"
POLL_INTERVAL = 30

EXCLUDE = {"mgmt", "ha", "npu0_vlink0", "npu0_vlink1", "ssl.root", "fortilink"}
prev_bytes = {}

def fetch_interfaces():
    try:
        r = requests.get(
            f"{FGT_HOST}/api/v2/monitor/system/interface",
            headers={"Authorization": f"Bearer {FGT_TOKEN}"},
            verify=False, timeout=10
        )
        r.raise_for_status()
        return r.json().get("results", {})
    except Exception as e:
        print(f"[{datetime.now()}] API error: {e}")
        return {}

def process(interfaces, ts_ns):
    global prev_bytes
    lines = []
    for iface_id, iface in interfaces.items():
        name = iface.get("name", iface_id)
        if name in EXCLUDE:
            continue
        if not iface.get("link", False):
            continue
        speed     = float(iface.get("speed", 0) or 0)
        tx_bytes  = int(iface.get("tx_bytes", 0) or 0)
        rx_bytes  = int(iface.get("rx_bytes", 0) or 0)
        tx_pkts   = int(iface.get("tx_packets", 0) or 0)
        rx_pkts   = int(iface.get("rx_packets", 0) or 0)
        tx_errors = int(iface.get("tx_errors", 0) or 0)
        rx_errors = int(iface.get("rx_errors", 0) or 0)
        tx_rate = rx_rate = 0
        if name in prev_bytes:
            p = prev_bytes[name]
            td = tx_bytes - p["tx_bytes"]
            rd = rx_bytes - p["rx_bytes"]
            if td >= 0 and rd >= 0:
                tx_rate = td / POLL_INTERVAL
                rx_rate = rd / POLL_INTERVAL
        prev_bytes[name] = {"tx_bytes": tx_bytes, "rx_bytes": rx_bytes}
        tag = f"interface={name},site=norrsken-kigali"
        fields = [
            f"link=1",
            f"speed_mbps={speed}",
            f"tx_bytes={tx_bytes}",
            f"rx_bytes={rx_bytes}",
            f"tx_packets={tx_pkts}",
            f"rx_packets={rx_pkts}",
            f"tx_errors={tx_errors}",
            f"rx_errors={rx_errors}",
            f"tx_rate_bps={tx_rate*8:.0f}",
            f"rx_rate_bps={rx_rate*8:.0f}"
        ]
        lines.append(f"fortigate_interface,{tag} {','.join(fields)} {ts_ns}")
        print(f"  {name:10s}: UP {speed:.0f}Mbps TX:{tx_rate*8/1000:.1f}Kbps RX:{rx_rate*8/1000:.1f}Kbps")
    return lines

def push(lines):
    if not lines:
        return
    try:
        r = requests.post(VM_URL, data="\n".join(lines), timeout=5)
        r.raise_for_status()
        print(f"  Pushed {len(lines)} metrics")
    except Exception as e:
        print(f"  VM push failed: {e}")

def main():
    print(f"[{datetime.now()}] FortiGate Interface Collector starting")
    while True:
        print(f"\n[{datetime.now()}] Polling...")
        ifaces = fetch_interfaces()
        if ifaces:
            push(process(ifaces, int(time.time() * 1_000_000_000)))
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
