# DSCP Verification Procedure
## Run this checklist every time a routing policy change is made

### What we are verifying
When FortiGate applies DSCP EF (Expedited Forwarding = decimal 46, binary 101110)
to real-time traffic, Peplink reads that marking and steers the traffic into the
SpeedFusion bond. This procedure proves the marking happened and the steering worked.

### Step 1 - Verify DSCP marking on FortiGate egress
Run on FortiGate CLI immediately after applying the policy change.

On FortiGate CLI:
  diagnose sniffer packet port16 'ip' 4 100
  diagnose sniffer packet port16 'ip[1] & 0xfc == 0xb8' 4 50

Expected: packets with TOS=0xb8 appearing for Zoom/Teams destinations.
If nothing appears: DSCP marking is not working, check firewall policy shaper.

### Step 2 - Verify in Elasticsearch
Run from mini-PC after the change:
  curl -sk -u 'elastic:PASSWORD' 'https://ES_IP:9200/logs-fortinet_fortigate.log-*/_search?pretty&size=5&q=network.application:Zoom'

Check that fortinet.firewall.dscp = 46 appears on Zoom/Teams sessions.

### Step 3 - Verify Peplink steering
In Peplink web UI:
  Network - SpeedFusion - confirm tunnel is UP
  Network - Outbound Policy - confirm DSCP EF rule is being matched
  Status - Active Sessions - confirm real-time sessions on bond interface

### Step 4 - Run iPerf3 with DSCP EF
From mini-PC:
  sudo iptables -t mangle -A OUTPUT -p udp --dport 5201 -j DSCP --set-dscp 46
  iperf3 -c VPS_IP -u -b 2M -t 30 -p 5201 --json
  sudo iptables -t mangle -D OUTPUT -p udp --dport 5201 -j DSCP --set-dscp 46

Compare jitter and loss to baseline values in VictoriaMetrics.

### Step 5 - Add Grafana annotation
  curl -s -u admin:$GF_ADMIN_PASSWORD -X POST http://localhost:3000/api/annotations \
    -H 'Content-Type: application/json' \
    -d '{"text":"DSCP policy applied - real-time traffic routed to SpeedFusion bond. Verified via packet capture.","tags":["config-change","dscp","speedfusion"]}'

### Pass criteria
  Packet capture shows DSCP 0xb8 on Zoom/Teams packets leaving port16
  ES query confirms dscp=46 on real-time app sessions
  Peplink shows sessions on bond interface
  iPerf3 UDP with DSCP EF shows improved jitter vs baseline
  Grafana annotation added with timestamp and description
